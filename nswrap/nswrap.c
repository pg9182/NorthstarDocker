// wayland-scanner server-header $(pkg-config --variable=pkgdatadir wayland-protocols)/stable/xdg-shell/xdg-shell.xml nswrap/xdg-shell-protocol.h
// wayland-scanner server-header $(pkg-config --variable=pkgdatadir wayland-protocols)/unstable/pointer-constraints/pointer-constraints-unstable-v1.xml nswrap/pointer-constraints-unstable-v1-protocol.h
// gcc -Wall -Wextra -Wno-unused-parameter -Inswrap $(pkg-config --cflags --libs pixman-1 'wlroots >= 0.16.0' wayland-server) nswrap/nswrap.c 

#define WLR_USE_UNSTABLE
#include <fcntl.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <wayland-server-core.h>
#include <wlr/backend.h>
#include <wlr/backend/session.h>
#include <wlr/backend/headless.h>
#include <wlr/render/wlr_renderer.h>
#include <wlr/render/pixman.h>
#include <wlr/types/wlr_compositor.h>
#include <wlr/types/wlr_xdg_shell.h>
#include <wlr/types/wlr_subcompositor.h>
#include <wlr/types/wlr_pointer_constraints_v1.h>
#include <wlr/types/wlr_relative_pointer_v1.h>
#include <wlr/util/log.h>

#define nswrap_log(verb, component, fmt, ...) \
    _wlr_log(verb, "[nswrap/%s] " fmt, component, ##__VA_ARGS__)

#define nswrap_log_errno(verb, component, fmt, ...) \
    nswrap_log(verb, component, fmt ": %s", ##__VA_ARGS__, strerror(errno))

/** The chunk size for console i/o (also the maximum length of a parsed title). */
#define NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE 256

/** The regexp for matching the console title against to extract the server status. */
#define NSWRAP_STATUS_RE(_x, _int, _str) _x( \
    " - ([A-Za-z0-9_]+) ([0-9]+)/([0-9]+) players \\(([A-Za-z0-9_]+)\\)", \
    _str(map_name) _int(player_count) _int(max_players) _str(playlist_name) \
)

/** The current status of a Northstar server */
struct ns_status {
    char title[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE + 1];
    char map_name[32];
    char playlist_name[32];
    int player_count;
    int max_players;
};

#define __NSWRAP_STATUS_RE_REGEXP(_r, _g) _r
#define NSWRAP_STATUS_RE_REGEXP NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_REGEXP, _, _)

#define __NSWRAP_STATUS_RE_GROUPS(_r, _g) do { _g } while (0)
#define NSWRAP_STATUS_RE_GROUPS(_int, _str) NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_GROUPS, _int, _str)

#define __NSWRAP_STATUS_RE_MATCHES_1(_r, _g) (1 _g)
#define __NSWRAP_STATUS_RE_MATCHES_2(_v) + 1
#define NSWRAP_STATUS_RE_MATCHES NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_MATCHES_1, __NSWRAP_STATUS_RE_MATCHES_2, __NSWRAP_STATUS_RE_MATCHES_2)

static void ns_status_str(const struct ns_status *st, char *buf, size_t buf_sz) {
    #define putf(fmt, ...) do { \
        if (buf_sz > 0) {       \
            int r = snprintf(buf, buf_sz, fmt, ##__VA_ARGS__); \
            if (r >= 0) {       \
                buf += r;       \
                buf_sz -= r;    \
            } else {            \
                return;         \
            }                   \
        }                       \
    } while (0)
    #define putft(cond, def, fmt, ...) do { \
        if (cond) {                         \
            putf(fmt, ##__VA_ARGS__);       \
        } else {                            \
            putf(def);                      \
        }                                   \
    } while (0)
    if (buf) {
        *buf = '\0';
        putft(st->player_count >= 0, "?", "%d", st->player_count);
        putft(st->max_players > 0, "/?", "/%d", st->max_players);
        putft(*st->map_name, " ???", " %s", st->map_name);
        putft(*st->playlist_name, " ???", " %s", st->playlist_name);
    }
    #undef putf
}

static struct {
    struct {
        const char *socket;
        struct wl_display *display;
        struct wlr_backend *backend;
        struct wlr_renderer *renderer;
        struct wlr_compositor *compositor;
        struct wlr_subcompositor *subcompositor;
        struct wlr_pointer_constraints_v1 *pointer_constraints_v1;
        struct wlr_relative_pointer_manager_v1 *relative_pointer_manager_v1;
        struct wlr_xdg_shell *xdg_shell;
    } wl;
    struct {
        int pty_master_fd;
        int pty_slave_fd; // not CLOEXEC
        int pty_slave_n;
        char pty_slave_fn[20];
        bool enable_color;
        regex_t title_re;

        int state;
        size_t n_inp, n_tit, n_out;
        char b_inp[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE];
        char b_tit[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE + 1]; // +1 for the null terminator
        char b_out[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE * 2 + 32]; // b_inp + b_tit + room for unprocessed escapes

        struct ns_status status;
        struct wl_signal status_updated;
    } ioproc;
} state;

static int handle_sigint(int signal_number, void *data) {
    wlr_log(WLR_ERROR, "sigint");
    wl_display_terminate(state.wl.display);
    return 0;
}

static int handle_ioproc_master(int fd, uint32_t mask, void *data) {
    ssize_t tmp;
    while ((tmp = read(state.ioproc.pty_master_fd, state.ioproc.b_inp, sizeof(state.ioproc.b_inp))) == -1) {
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to read output pty");
        }
        return 0;
    }
    state.ioproc.n_inp = (size_t)(tmp); // note: not EPOLLET, so we don't need to read it all at once; it'll just be triggered again later

    // fast path when no escape sequences in the buffer
    if (state.ioproc.state == 0) {
        for (size_t i = 0; i < state.ioproc.n_inp; i++) {
            if (state.ioproc.b_inp[i] == 0x1B) {
                goto slow;
            }
        }
        fwrite(state.ioproc.b_inp, 1, state.ioproc.n_inp, stdout);
        fflush(stdout);
        return 0;
    }

slow:
    state.ioproc.n_out = 0;
    for (size_t i = 0; i < state.ioproc.n_inp; i++) {
        char c = state.ioproc.b_inp[i];
        switch (state.ioproc.state) {
        case 0: // normal output
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case 0x1B:
                state.ioproc.state = 1;
                break;
            }
            break;
        case 1: // at \x1B
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case ']':
                state.ioproc.state = 2;
                break;
            case '[':
                state.ioproc.state = 12;
                break;
            }
            break;
        case 2: // at \x1B]
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = ']';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case '0':
                state.ioproc.state = 3;
                break;
            }
            break;
        case 3: // at \x1B]0
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = ']';
                state.ioproc.b_out[state.ioproc.n_out++] = '0';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case ';':
                state.ioproc.state = 4;
                state.ioproc.n_tit = 0;
                break;
            }
            break;
        case 4: // in \x1B]0;
            switch (c) {
            default:
                // next title char
                if (state.ioproc.n_tit < NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE) {
                    state.ioproc.b_tit[state.ioproc.n_tit++] = c;
                    break;
                }
                __attribute__((fallthrough));
            case 0x07:
                // end of title || overflow
                if (state.ioproc.n_tit == NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE) {
                    state.ioproc.state = 5;
                } else {
                    state.ioproc.state = 0;
                }
                {
                    memcpy(state.ioproc.status.title, state.ioproc.b_tit, state.ioproc.n_tit);
                    state.ioproc.status.title[state.ioproc.n_tit] = '\0';
                    regmatch_t m[NSWRAP_STATUS_RE_MATCHES];
                    int rc;
                    if ((rc = regexec(&state.ioproc.title_re, state.ioproc.status.title, NSWRAP_STATUS_RE_MATCHES, m, 0))) {
                        if (rc != REG_NOMATCH) {
                            char err[512];
                            regerror(rc, &state.ioproc.title_re, err, sizeof(err));
                            nswrap_log(WLR_ERROR, "ioproc", "Failed to match title regex: %s", err);
                        }
                        errno = EINVAL;
                        return -1;
                    }
                    int i = 0;
                    #define m_str(_v) \
                        i++; snprintf(state.ioproc.status._v, sizeof(state.ioproc.status._v), "%.*s", (int)(m[i].rm_eo - m[i].rm_so), state.ioproc.status.title + m[i].rm_so);
                    #define m_int(_v) \
                        i++; state.ioproc.status._v = 0; for (regoff_t j = m[i].rm_so; j < m[i].rm_eo; j++) { state.ioproc.status._v = 10 * state.ioproc.status._v + (state.ioproc.status.title[j] - '0'); };
                    NSWRAP_STATUS_RE_GROUPS(m_int, m_str);
                    #undef m_str
                    #undef m_int
                    return 0;
                }
                wl_signal_emit_mutable(&state.ioproc.status_updated, NULL);
                state.ioproc.n_tit = 0;
                break;
            case 0x1B:
                // start of a new escape sequence (this shouldn't happen)
                state.ioproc.state = 1;
                break;
            }
            break;
        case 5: // in title
            switch (c) {
            default:
                // overflowing title character
                break;
            case 0x07:
                // end of the overflowing title
                state.ioproc.state = 0;
                break;
            case 0x1B:
                // start of a new escape sequence (this shouldn't happen)
                state.ioproc.state = 1;
                break;
            }
            break;
        case 12: // at \x1B[
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = '[';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case '?':
                state.ioproc.state = 13;
                break;
            case '1':
                state.ioproc.state = 23;
                break;
            case 'm': // text attr: end
                state.ioproc.state = 0;
                break;
            case '3': // text attr: foreground
            case '4': // text attr: background
            case '9': // text attr: foreground light
                if (state.ioproc.enable_color) {
                    state.ioproc.state = 0;
                    state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                    state.ioproc.b_out[state.ioproc.n_out++] = '[';
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                } else {
                    state.ioproc.state = 33;
                }
                break;
            case 'K':
                // ignore the CR equivalent
                state.ioproc.state = 0;
                break;
            }
            break;
        case 13: // at \x1B[?
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = '[';
                state.ioproc.b_out[state.ioproc.n_out++] = '?';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case '2':
                state.ioproc.state = 14;
                break;
            }
            break;
        case 14: // at \x1B[?2
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = '[';
                state.ioproc.b_out[state.ioproc.n_out++] = '?';
                state.ioproc.b_out[state.ioproc.n_out++] = '2';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case '5':
                state.ioproc.state = 15;
                break;
            }
            break;
        case 15: // at \x1B[?25
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = '[';
                state.ioproc.b_out[state.ioproc.n_out++] = '?';
                state.ioproc.b_out[state.ioproc.n_out++] = '2';
                state.ioproc.b_out[state.ioproc.n_out++] = '5';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case 'l':
                // ignore hide cursor
                state.ioproc.state = 0;
                break;
            case 'h':
                // ignore show cursor
                state.ioproc.state = 0;
                break;
            }
            break;
        case 23: // at \x1B[1
            switch (c) {
            default:
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                state.ioproc.b_out[state.ioproc.n_out++] = '[';
                state.ioproc.b_out[state.ioproc.n_out++] = '1';
                state.ioproc.b_out[state.ioproc.n_out++] = c;
                break;
            case 'C':
                // move cursor right 1
                state.ioproc.state = 0;
                state.ioproc.b_out[state.ioproc.n_out++] = ' ';
                break;
            }
            break;
        case 33: // inside text attributes (i.e., ignore anything until an invalid attr char or an 'm' to terminate it)
            if (c == ';')
                break; // separator
            if (c >= '0' && c <= '9')
                break; // attribute
            if (c != 'm')
                state.ioproc.b_out[state.ioproc.n_out++] = c; // invalid char, so output it
            state.ioproc.state = 0;
            break;
        }
    }
    fwrite(state.ioproc.b_inp, 1, state.ioproc.n_inp, stdout);
    fflush(stdout);
    return 0;
}

int main(void) {
    wlr_log_init(WLR_DEBUG, NULL);

    // wayland
    {
        state.wl.socket = "/tmp/nswrap-wayland";

        // initialize wayland
        if (!(state.wl.display = wl_display_create())) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wl_display");
            goto cleanup;
        }
        if (!(state.wl.backend = wlr_headless_backend_create(state.wl.display))) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_headless_backend");
            goto cleanup;
        }
        if (!wlr_backend_start(state.wl.backend)) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to start backend");
            goto cleanup;
        }
        if (!(state.wl.renderer = wlr_pixman_renderer_create())) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_pixman_renderer");
            goto cleanup;
        }
        if (wl_display_add_socket(state.wl.display, state.wl.socket)) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create socket");
            goto cleanup;
        }
        if (setenv("WAYLAND_DISPLAY", state.wl.socket, 1)) {
            nswrap_log_errno(WLR_ERROR, "wayland", "Failed to set env WAYLAND_DISPLAY");
            goto cleanup;
        }
        if (unsetenv("DISPLAY")) {
            nswrap_log_errno(WLR_ERROR, "wayland", "Failed to unset env DISPLAY");
            goto cleanup;
        }

        // required protocols for winewayland.drv
        if (!wlr_renderer_init_wl_shm(state.wl.renderer, state.wl.display)) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to initialize wl_shm on renderer");
            goto cleanup;
        }
        if (!(state.wl.compositor = wlr_compositor_create(state.wl.display, state.wl.renderer))) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_compositor");
            goto cleanup;
        }
        if (!(state.wl.subcompositor = wlr_subcompositor_create(state.wl.display))) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_subcompositor");
            goto cleanup;
        }
        if (!(state.wl.pointer_constraints_v1 = wlr_pointer_constraints_v1_create(state.wl.display))) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_pointer_constraints_v1");
            goto cleanup;
        }
        if (!(state.wl.relative_pointer_manager_v1 = wlr_relative_pointer_manager_v1_create(state.wl.display))) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_relative_pointer_manager_v1");
            goto cleanup;
        }
        if (!(state.wl.xdg_shell = wlr_xdg_shell_create(state.wl.display, 5))) {
            nswrap_log(WLR_ERROR, "wayland", "Failed to create wlr_xdg_shell");
            goto cleanup;
        }
    }
    struct wl_event_loop *loop = wl_display_get_event_loop(state.wl.display);

    // ioproc
    {
        nswrap_log(WLR_DEBUG, "ioproc", "Initializing");

        if ((state.ioproc.pty_master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC)) == -1) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to allocate pty master");
            goto cleanup;
        }
        if (ioctl(state.ioproc.pty_master_fd, TIOCSPTLCK, &(int) {0}) == -1) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to unlock pty master");
            goto cleanup;
        }
        if (ioctl(state.ioproc.pty_master_fd, TIOCGPTN, &state.ioproc.pty_slave_n) == -1) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to get pty slave");
            goto cleanup;
        }
        if (snprintf(state.ioproc.pty_slave_fn, sizeof(state.ioproc.pty_slave_fn), "/dev/pts/%d", state.ioproc.pty_slave_n) == -1) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to get build pty slave filename");
            goto cleanup;
        }
        if ((state.ioproc.pty_slave_fd = open(state.ioproc.pty_slave_fn, O_RDWR | O_NOCTTY)) == -1) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to open slave");
            goto cleanup;
        }
        {
            struct termios pty_termios;
            if (tcgetattr(state.ioproc.pty_slave_fd, &pty_termios)) {
                nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to get pty slave termios");
                goto cleanup;
            }
            pty_termios.c_iflag = BRKINT | IGNPAR | ISTRIP | IGNCR | IUTF8;
            pty_termios.c_oflag = OPOST | ONOCR;
            pty_termios.c_cflag = CREAD;
            pty_termios.c_lflag = ISIG | ICANON;
            // return from read() at least every 0.1s, whether or not data is available
            pty_termios.c_cc[VMIN] = 0;
            pty_termios.c_cc[VTIME] = 1;
            if (tcsetattr(state.ioproc.pty_slave_fd, TCSANOW, &pty_termios)) {
                nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to set pty slave termios");
                goto cleanup;
            }
        }
        if (ioctl(state.ioproc.pty_slave_fd, TIOCSWINSZ, &(struct winsize) {
            .ws_col = 1200, // so wine doesn't cut off lines
            .ws_row = 25,
        })) {
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to set pty slave winsize");
            goto cleanup;
        }
        state.ioproc.enable_color = !!isatty(STDIN_FILENO);

        int rc;
        #define x(_n, _r, _g) _r
        if ((rc = regcomp(&state.ioproc.title_re, NSWRAP_STATUS_RE_REGEXP, REG_EXTENDED) ? -1 : 0)) {
            char err[512];
            regerror(rc, &state.ioproc.title_re, err, sizeof(err));
            nswrap_log_errno(WLR_ERROR, "ioproc", "Failed to compile title regex: %s", err);
            goto cleanup;
        }
        #undef x

        wl_signal_init(&state.ioproc.status_updated);
        wl_event_loop_add_fd(loop, state.ioproc.pty_master_fd, WL_EVENT_READABLE, handle_ioproc_master, NULL);
    }

    wl_event_loop_add_signal(loop, SIGINT, handle_sigint, NULL);

    wl_display_run(state.wl.display);

cleanup:
    // wayland
    {
        if (state.ioproc.pty_slave_fd > 0) {
            close(state.ioproc.pty_slave_fd);
        }
        if (state.ioproc.pty_master_fd > 0) {
            close(state.ioproc.pty_master_fd);
        }
        if (state.wl.display) {
            wl_display_destroy(state.wl.display); // note: this includes most other objects attached to the display
        }
        if (state.wl.renderer) {
            wlr_renderer_destroy(state.wl.renderer);
        }
    }
    return 1;
}
