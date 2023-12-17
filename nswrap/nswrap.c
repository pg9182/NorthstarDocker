// wayland-scanner server-header $(pkg-config --variable=pkgdatadir wayland-protocols)/stable/xdg-shell/xdg-shell.xml nswrap/xdg-shell-protocol.h
// wayland-scanner server-header $(pkg-config --variable=pkgdatadir wayland-protocols)/unstable/pointer-constraints/pointer-constraints-unstable-v1.xml nswrap/pointer-constraints-unstable-v1-protocol.h
// gcc -Wall -Wextra -Wno-unused-parameter -Inswrap $(pkg-config --cflags --libs pixman-1 'wlroots >= 0.16.0' wayland-server) nswrap/nswrap.c 

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
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
#include <sys/prctl.h>
#include <sys/wait.h>

#define WLR_USE_UNSTABLE
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
    _wlr_log(verb, "[nswrap/%s] " fmt, component ?: "core", ##__VA_ARGS__)

#define nswrap_log_errno(verb, component, fmt, ...) \
    nswrap_log(verb, component, fmt ": %s", ##__VA_ARGS__, strerror(errno))

/** Whether to pass-through the title if stdout is a TTY. **/
#define NSWRAP_IOPROC_TTY_TITLE true

/** Whether to pass-through colors if stdout is a TTY. **/
#define NSWRAP_IOPROC_TTY_COLOR true

/** The chunk size for console i/o (also the maximum length of a parsed title). */
#define NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE 256

/** The regexp for matching the console title against to extract the server status. */
#define NSWRAP_STATUS_RE(_x, _int, _str) _x( \
    " - ([A-Za-z0-9_]+) ([0-9]+)/([0-9]+) players \\(([A-Za-z0-9_]+)\\)", \
    _str(map_name) _int(player_count) _int(max_players) _str(playlist_name) \
)

/** Like getenv, but gets the entire variable. */
static char *getenve(const char *name) {
    extern char **environ;
    int i;
    size_t l = strlen(name);
    if (!environ || !*name || strchr(name, '=')) {
        return NULL;
    }
    for (i = 0; environ[i] && (strncmp(name, environ[i], l) || environ[i][l] != '='); i++) {
        continue;
    }
    if (environ[i]) {
        return environ[i];
    }
    return NULL;
}

/** Replace the process cmdline. It must be initialized by calling it with a NULL fmt first. */
static __attribute__ ((__format__ (__printf__, 2, 3))) int setproctitle(char **argv, const char *fmt, ...) {
    // https://github.com/torvalds/linux/commit/d26d0cd97c88eb1a5704b42e41ab443406807810
    // https://source.chromium.org/chromium/chromium/src/+/master:content/common/set_process_title_linux.cc

    static int argv_len = 0;
    if (!fmt) {
        for (char **x = argv; *x; x++) {
            if (*x != *argv + argv_len) {
                // next arg is not consecutive, so stop here
                break;
            }
            argv_len += strlen(*x) + 1;
        }
        return argv_len;
    }

    va_list a;
    va_start(a, fmt);
    int r = vsnprintf(*argv, argv_len, fmt, a);
    for (char *x = *argv; x < *argv + argv_len; x++) {
        if (x == *argv + argv_len-1) {
            *x = '.';
        } else if (x >= *argv + r || x == *argv + argv_len-2) {
            *x = '\0';
        }
    }
    va_end(a);
    return r;
}

#define __NSWRAP_STATUS_RE_REGEXP(_r, _g) _r
#define NSWRAP_STATUS_RE_REGEXP NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_REGEXP, _, _)

#define __NSWRAP_STATUS_RE_GROUPS(_r, _g) do { _g } while (0)
#define NSWRAP_STATUS_RE_GROUPS(_int, _str) NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_GROUPS, _int, _str)

#define __NSWRAP_STATUS_RE_MATCHES_1(_r, _g) (1 _g)
#define __NSWRAP_STATUS_RE_MATCHES_2(_v) + 1
#define NSWRAP_STATUS_RE_MATCHES NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_MATCHES_1, __NSWRAP_STATUS_RE_MATCHES_2, __NSWRAP_STATUS_RE_MATCHES_2)

static struct {
    char **argv;
    const char *proctitle;

    struct {
        char *socket;
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
        bool isatty;
        regex_t title_re;

        int state;
        size_t n_inp, n_tit, n_out;
        char b_inp[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE];
        char b_tit[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE + 1]; // +1 for the null terminator
        char b_out[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE * 2 + 32]; // b_inp + b_tit + room for unprocessed escapes

        struct {
            char title[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE + 1];

            bool parsed;
            char map_name[32];
            char playlist_name[32];
            int player_count;
            int max_players;
        } status;
        struct wl_signal status_updated;
    } ioproc;
    struct {
        char *argv[256];
        char *envp[256];
        int errno_pipe[2];
        pid_t proc_pid;
        bool proc_exited;
        int proc_wstatus;
        int shutdown_count;
        struct wl_signal exited;
    } wine;
} state;

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
                if (NSWRAP_IOPROC_TTY_TITLE && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                    state.ioproc.b_out[state.ioproc.n_out++] = ']';
                    state.ioproc.b_out[state.ioproc.n_out++] = '0';
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                }
                state.ioproc.state = 4;
                state.ioproc.n_tit = 0;
                break;
            }
            break;
        case 4: // in \x1B]0;
            switch (c) {
            default:
                if (NSWRAP_IOPROC_TTY_TITLE && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                }
                // next title char
                if (state.ioproc.n_tit < NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE) {
                    state.ioproc.b_tit[state.ioproc.n_tit++] = c;
                    break;
                }
                __attribute__((fallthrough));
            case 0x07:
                if (NSWRAP_IOPROC_TTY_TITLE && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                }
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
                        state.ioproc.status.parsed = false;
                    } else {
                        int i = 0;
                        #define m_str(_v) \
                            i++; snprintf(state.ioproc.status._v, sizeof(state.ioproc.status._v), "%.*s", (int)(m[i].rm_eo - m[i].rm_so), state.ioproc.status.title + m[i].rm_so);
                        #define m_int(_v) \
                            i++; state.ioproc.status._v = 0; for (regoff_t j = m[i].rm_so; j < m[i].rm_eo; j++) { state.ioproc.status._v = 10 * state.ioproc.status._v + (state.ioproc.status.title[j] - '0'); };
                        NSWRAP_STATUS_RE_GROUPS(m_int, m_str);
                        #undef m_str
                        #undef m_int
                        state.ioproc.status.parsed = true;
                    }
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
                if (NSWRAP_IOPROC_TTY_TITLE && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                }
                // overflowing title character
                break;
            case 0x07:
                if (NSWRAP_IOPROC_TTY_TITLE && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                }
                // end of the overflowing title
                state.ioproc.state = 0;
                break;
            case 0x1B:
                if (NSWRAP_IOPROC_TTY_TITLE && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = 0x07; // end the title
                }
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
                if (NSWRAP_IOPROC_TTY_COLOR && state.ioproc.isatty) {
                    state.ioproc.b_out[state.ioproc.n_out++] = 0x1B;
                    state.ioproc.b_out[state.ioproc.n_out++] = '[';
                    state.ioproc.b_out[state.ioproc.n_out++] = c;
                }
                state.ioproc.state = 33;
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
            if (NSWRAP_IOPROC_TTY_COLOR && state.ioproc.isatty) {
                state.ioproc.b_out[state.ioproc.n_out++] = c;
            }
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
    if (state.ioproc.n_out) {
        fwrite(state.ioproc.b_out, 1, state.ioproc.n_out, stdout);
        fflush(stdout);
    }
    return 0;
}

static int handle_wine_errno(int fd, uint32_t mask, void *data) {
    int n;
    if (read(state.wine.errno_pipe[0], &n, sizeof(n)) == -1) {
        nswrap_log_errno(WLR_ERROR, "wine", "Failed to start process, and failed to read errno pipe");
    } else {
        errno = n;
        nswrap_log_errno(WLR_ERROR, "wine", "Failed to start process");
    }
    wl_display_terminate(state.wl.display);
    return 0;
}

static void handle_wine_exited(struct wl_listener *listener, void *data) {
    if (WIFSIGNALED(state.wine.proc_wstatus)) {
        nswrap_log(WLR_INFO, "wine", "Wine killed by signal %d", WTERMSIG(state.wine.proc_wstatus));
    } else {
        nswrap_log(WLR_INFO, "wine", "Wine exited with status %d", WEXITSTATUS(state.wine.proc_wstatus));
    }
}

static void handle_proctitle(struct wl_listener *listener, void *data) {
    if (state.ioproc.status.parsed) {
        char buf[512];
        char *cur = buf, *end = buf + sizeof(buf);
        #define putf(fmt, ...) do { \
            if (cur < end) { \
                int r = snprintf(cur, end - cur, fmt, ##__VA_ARGS__); \
                if (r >= 0) cur += r; \
            } \
        } while (0)
        #define putft(cond, def, fmt, ...) do { \
            if (cond) putf(fmt, ##__VA_ARGS__); \
            else putf("%s", def); \
        } while (0)
        *buf = '\0';
        putft(state.ioproc.status.player_count >= 0, "?", "%d", state.ioproc.status.player_count);
        putft(state.ioproc.status.max_players > 0, "/?", "/%d", state.ioproc.status.max_players);
        putft(*state.ioproc.status.map_name, " ???", " %s", state.ioproc.status.map_name);
        putft(*state.ioproc.status.playlist_name, " ???", " %s", state.ioproc.status.playlist_name);
        #undef putf
        #undef putft
        if (*state.proctitle) {
            setproctitle(state.argv, "northstar %s [%s]", state.proctitle, buf);
        } else {
            setproctitle(state.argv, "northstar [%s]", buf);
        }
    } else {
        if (*state.proctitle) {
            setproctitle(state.argv, "northstar %s", state.proctitle);
        } else {
            setproctitle(state.argv, "northstar");
        }
    }
}

static int handle_sigchld(int signal_number, void *data) {
    pid_t pid;
    int wstatus;
    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
        if (pid == state.wine.proc_pid) {
            state.wine.proc_exited = true;
            state.wine.proc_wstatus = wstatus;
            wl_signal_emit_mutable(&state.wine.exited, NULL);
            wl_display_terminate(state.wl.display);
        }
    }
    return 0;
}

static int handle_shutdown(int signal_number, void *data) {
    if (state.wine.proc_pid) {
        switch (++state.wine.shutdown_count) {
        case 1:
            nswrap_log(WLR_INFO, NULL, "Received first shutdown signal, requesting game server exit");
            kill(state.wine.proc_pid, SIGTERM);
            // TODO: send proper quit to server
            break;
        case 2:
            nswrap_log(WLR_INFO, NULL, "Received second shutdown signal, terminating wine");
            kill(state.wine.proc_pid, SIGTERM);
            break;
        case 3:
            nswrap_log(WLR_INFO, NULL, "Received third shutdown signal, killing wine");
            kill(state.wine.proc_pid, SIGKILL);
            break;
        default:
            nswrap_log(WLR_INFO, NULL, "Received multiple shutdown signals, forcefully terminating");
            wl_display_terminate(state.wl.display);
            break;
        }
    } else {
        wl_display_terminate(state.wl.display);
    }
    return 0;
}

int main(int argc, char **argv) {
    // init setproctitle and attempt to ensure there is a placeholder arg consisting of spaces
    if (argc > 0) {
        if (!argv[argc - 1] || *argv[argc - 1] != ' ') {
            extern char **environ;
            char **nargv = alloca((argc + 2)*sizeof(char*));
            memcpy(nargv, argv, argc*sizeof(char*));
            nargv[argc] = "                                                                                                                                ";
            nargv[argc+1] = NULL;
            if (execve("/proc/self/exe", nargv, environ) == -1) {
                fprintf(stderr, "warning: failed to self-exec with additional space in argv for process title failed: execve: %s\n", strerror(errno));
            }
        } else {
            argc--;
            setproctitle(argv, NULL);
            argv[argc] = NULL;
        }
    }
    state.argv = argv;

    wlr_log_init(WLR_INFO, NULL);
    {
        int opt;
        bool has_dedicated = false;
        int getopt_argc = 0;
        char **getopt_argv = alloca(argc * sizeof(char*) + 1);
        for (int i = 0; i < argc; i++) {
            if (i && !strcmp(argv[i], "-dedicated")) {
                has_dedicated = true;
                break;
            }
            getopt_argv[getopt_argc++] = argv[i];
            getopt_argv[getopt_argc] = NULL;
        }
        while ((opt = getopt(getopt_argc, getopt_argv, "hvC:t::")) != -1) {
            switch (opt) {
            case 'v':
                wlr_log_init(WLR_DEBUG, NULL);
                break;
            case 'C':
                if (chdir(optarg)) {
                    nswrap_log_errno(WLR_ERROR, NULL, "Failed to chdir to '%s'\n", optarg);
                    exit(1);
                }
            case 't':
                state.proctitle = strdupa(optarg ?: "");
                break;
            default:
                fprintf(stderr,
                    "usage: %s [options] -dedicated [northstar_options]\n"
                    "  -h        show this help text\n"
                    "  -v        use verbose logging\n"
                    "  -C dir    chdir to the provided directory\n"
                    "  -tlabel   set the process title, including label if provided\n",
                    argv[0] ?: "nswrap");
                exit(1);
            }
        }
        if (!has_dedicated) {
            nswrap_log_errno(WLR_ERROR, NULL, "Must contain -dedicated argument (see `%s -h`)\n", argv[0] ?: "nswrap");
            exit(1);
        }
    }

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    if (access("NorthstarLauncher.exe", F_OK)) {
        nswrap_log_errno(WLR_ERROR, NULL, "NorthstarLauncher.exe is missing");
        exit(1);
    }

    // wayland
    {
        if (!(state.wl.socket = tempnam(NULL, "nswl."))) {
            nswrap_log_errno(WLR_ERROR, "wayland", "Failed to create temp file for socket");
            goto cleanup;
        }

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
        state.ioproc.isatty = !!isatty(STDOUT_FILENO);

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

    // wine
    {
        size_t i;

        // build argv
        i=0;
        state.wine.argv[i++] = strdupa("wine64");
        state.wine.argv[i++] = strdupa("NorthstarLauncher.exe");
        state.wine.argv[i++] = strdupa("-dedicated");
        for (int j = optind; j < argc; j++) {
            if (i >= sizeof(state.wine.argv)/(sizeof(*state.wine.argv))) {
                nswrap_log(WLR_ERROR, "wine", "Too many arguments");
                goto cleanup;
            }
            state.wine.argv[i++] = strdupa(argv[j]);
        }

        // build envp
        i=0;
        state.wine.envp[i++] = strdupa("USER=none");
        state.wine.envp[i++] = strdupa(getenve("HOME") ?: "HOME=/");
        state.wine.envp[i++] = strdupa(getenve("USER") ?: "USER=none");
        state.wine.envp[i++] = strdupa(getenve("HOSTNAME") ?: "HOSTNAME=none");
        state.wine.envp[i++] = strdupa(getenve("PATH") ?: "PATH=/usr/local/bin:/bin:/usr/bin");
        state.wine.envp[i++] = strdupa(getenve("WINEDEBUG") ?: "WINEDEBUG=fixme-secur32,fixme-bcrypt,fixme-ver,err-wldap32");
        {
            const char *tmp1 = "WAYLAND_DISPLAY=";
            const int tmp2 = strlen(state.wl.socket);
            char *tmp3 = alloca(strlen(tmp1) + tmp2 + 1);
            memcpy(tmp3, tmp1, strlen(tmp1));
            memcpy(tmp3 + strlen(tmp1), state.wl.socket, tmp2);
            tmp3[strlen(tmp1) + tmp2] = '\0';
            state.wine.envp[i++] = tmp3;
        }
        if (getenve("WINEPREFIX")) {
            state.wine.envp[i++] = strdupa(getenve("WINEPREFIX"));
        }
        if (getenve("WINESERVER")) {
            state.wine.envp[i++] = strdupa(getenve("WINESERVER"));
        }

        // errno pipe
        if (pipe2(state.wine.errno_pipe, O_DIRECT | O_NONBLOCK)) {
            nswrap_log_errno(WLR_ERROR, "wine", "Failed to create errno pipe");
            return 1;
        }
        wl_event_loop_add_fd(loop, state.wine.errno_pipe[0], WL_EVENT_READABLE, handle_wine_errno, NULL);

        // exit handler
        wl_signal_init(&state.wine.exited);
        {
            struct wl_listener *listener = alloca(sizeof(struct wl_listener));
            *listener = (struct wl_listener){ .notify = handle_wine_exited };
            wl_signal_add(&state.wine.exited, listener);
        }

        // start process
        if (!(state.wine.proc_pid = fork())) {
            setsid();
            ioctl(state.ioproc.pty_slave_fd, TIOCSCTTY, 0);
            dup2(state.ioproc.pty_slave_fd, 0);
            dup2(state.ioproc.pty_slave_fd, 1);
            dup2(state.ioproc.pty_slave_fd, 2);
            close(state.ioproc.pty_slave_fd);
            close(state.wine.errno_pipe[0]);
            execvpe(state.wine.argv[0], state.wine.argv, state.wine.envp);
            const int n = errno;
            write(state.wine.errno_pipe[1], &n, sizeof(n));
            close(state.wine.errno_pipe[1]);
            _exit(127);
        }
    }

    // proctitle
    if (state.proctitle) {
        struct wl_listener *listener = alloca(sizeof(struct wl_listener));
        *listener = (struct wl_listener){ .notify = handle_proctitle };
        wl_signal_add(&state.ioproc.status_updated, listener);
        listener->notify(listener, NULL);
    }

    wl_event_loop_add_signal(loop, SIGCHLD, handle_sigchld, NULL);
    wl_event_loop_add_signal(loop, SIGINT, handle_shutdown, NULL);
    wl_event_loop_add_signal(loop, SIGTERM, handle_shutdown, NULL);

    wl_display_run(state.wl.display);

cleanup:
    nswrap_log(WLR_INFO, NULL, "Cleaning up");

    // wine
    if (state.wine.proc_pid && !state.wine.proc_exited) {
        nswrap_log(WLR_INFO, "wine", "Wine hasn't exited; killing");
        if (kill(state.wine.proc_pid, SIGKILL)) {
            if (errno != ESRCH) {
                nswrap_log_errno(WLR_ERROR, "wine", "Failed to kill pid %d", (int)(state.wine.proc_pid));
            }
        }
    }

    // ioproc
    if (state.ioproc.pty_slave_fd > 0) {
        close(state.ioproc.pty_slave_fd);
    }
    if (state.ioproc.pty_master_fd > 0) {
        close(state.ioproc.pty_master_fd);
    }

    // wayland
    if (state.wl.display) {
        wl_display_destroy(state.wl.display); // note: this includes most other objects attached to the display
    }
    if (state.wl.socket) {
        const char *tmp1 = ".lock";
        const int tmp2 = strlen(state.wl.socket);
        char *tmp3 = alloca(tmp2 + strlen(tmp1) + 1);
        memcpy(tmp3, state.wl.socket, tmp2);
        memcpy(tmp3 + strlen(tmp1), tmp1, strlen(tmp1));
        tmp3[strlen(tmp1) + tmp2] = '\0';
        remove(state.wl.socket);
        remove(tmp3);
    }

    // reap children
    {
        nswrap_log(WLR_INFO, NULL, "Waiting for children to exit");
        struct timespec ts, tc;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        tc = ts;
        for (;;) {
            pid_t pid;
            int wstatus;
            switch ((pid = waitpid(-1, &wstatus, WNOHANG))) {
            case -1:
                if (errno != EINTR) {
                    if (errno != ECHILD) {
                        nswrap_log_errno(WLR_INFO, NULL, "Failed to wait for children");
                    }
                    goto doneReap; // no children
                }
                continue; // interrupted, try again immediately
            case 0:
                clock_gettime(CLOCK_MONOTONIC, &tc);
                if (tc.tv_sec - ts.tv_sec > 4) {
                    nswrap_log(WLR_ERROR, NULL, "Children did not exit in time");
                    goto doneReap;
                } else {
                    nanosleep(&(struct timespec){
                        .tv_nsec = 100 * 1000 * 1000,
                    }, NULL);
                }
                continue; // children exist, but haven't changed state; try again
            default:
                if (pid == state.wine.proc_pid) {
                    state.wine.proc_exited = true;
                    state.wine.proc_wstatus = wstatus;
                    wl_signal_emit_mutable(&state.wine.exited, NULL);
                }
                continue; // child reaped; try another one immediately
            }
        }
        doneReap:;
    }

    exit(state.wine.shutdown_count ? 0 : 1);
}
