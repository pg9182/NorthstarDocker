/**
 * nswrap v2
 *
 * - dependencies:
 *   - linux 5.2+ (why: setproctitle, signalfd, timerfd, etc)
 *   - wine 9.0+ 64-bit (why: works properly with r2 with nulldrv, relocatable wine lib dir, other fixes)
 *     - must have prepared wineprefix
 *     - must be patched to use nulldrv by default
 *     - must have d3d11 dll override (why: so stubs work)
 *     - must have mscoree/mshtml/winemenubuilder disabled with dll override or removed (why: so they don't interfere with stuff by showing dialogs about installing mono/gecko)
 *     - must have HKCU\Software\Wine\WineDbg\ShowCrashDialog=REG_DWORD:1 (why: so crash dialogs don't just sit there invisible)
 *     - must have HKCU\Software\Wine\Version=REG_SZ:win10
 *     - must have wine runtime deps: libunwind, gnutls, freetype, fontconfig
 *     - must have host tzdata/ca_certificates/resolv
 *     - wineserver persistence should be disabled for faster cleanup
 *   - glibc (why: works properly with wine and ns)
 *   - northstar v(see compat file) (why: proper console/stdin/log handling, process title update format, dedicated patches)
 *   - northstar d3d11/gfsdk stubs (why: nulldrv)
 *   - arm64: box64 9b23c3272bd6e0cffef50e811627301e0b64ea42+
 * - functionality:
 *   - fake stdin/stdout/stderr tty
 *     - prevent log line cutoff by emulating wider screen
 *     - title update watchdog
 *     - title update to process title
 *     - ansi escape filtering
 *     - proper stdin handling (buffering, tty, etc)
 *   - env var filtering
 *   - process monitoring
 *   - cleanup
 *   - experimental arm64 support via box64
 *
 * To test this without a patched wine build (it still must be >= wine-9.0), do something like the following:
 * - gcc -Wall -Wextra nswrap.c -o nswrap
 * - unset DISPLAY WAYLAND_DISPLAY
 * - export WINEARCH=win64 WINEDLLOVERRIDES="mscoree,mshtml,winemenubuilder.exe="
 * - export WINEPREFIX=/tmp/whatever/wineprefix/path
 * - rm -rf $WINEPREFIX
 * - wine64 wineboot --init
 * - wine64 reg add 'HKCU\Software\Wine' /v 'Version' /t REG_SZ /d 'win10' /f
 * - wine64 reg add 'HKCU\Software\Wine\Drivers' /v 'Audio' /t REG_SZ /d '' /f
 * - wine64 reg add 'HKCU\Software\Wine\WineDbg' /v 'ShowCrashDialog' /t REG_DWORD /d 0 /f
 * - wine64 reg add 'HKCU\Software\Wine\Drivers' /v 'Graphics' /t REG_SZ /d 'null' /f
 * - wine64 reg add 'HKCU\Software\Wine\DllOverrides' /v 'mscoree' /t REG_SZ /d '' /f
 * - wine64 reg add 'HKCU\Software\Wine\DllOverrides' /v 'mshtml' /t REG_SZ /d '' /f
 * - wine64 reg add 'HKCU\Software\Wine\DllOverrides' /v 'winemenubuilder' /t REG_SZ /d '' /f
 * - wine64 reg add 'HKCU\Software\Wine\DllOverrides' /v 'd3d11' /t REG_SZ /d 'native' /f
 * - wine64 wineboot --shutdown --force
 * - wine64 wineboot --kill --force
 * - export NSWRAP_DEBUG=1 NSWRAP_EXTWINE=1 NSWRAP_RUNTIME=$PWD
 * - env -C /path/to/northstar ./nswrap -dedicated ...
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <regex.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifndef __x86_64__
#ifndef __aarch64__
#error unsupported platform
#endif
#endif

/** Watchdog timeout (initial). */
#define NSWRAP_WATCHDOG_TIMEOUT_INITIAL (4*60)

/** Watchdog timeout. */
#define NSWRAP_WATCHDOG_TIMEOUT 30

/** Whether to pass-through the title if stdout is a TTY. */
#define NSWRAP_IOPROC_TTY_TITLE true

/** Whether to pass-through colors if stdout is a TTY. */
#define NSWRAP_IOPROC_TTY_COLOR true

/** The chunk size for console i/o (also the maximum length of a parsed title and stdin concommand). */
#define NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE 2048

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

/** Replace the process cmdline. The first call must have argv to initialize it. If fmt is NULL, the max length is returned, otherwise the return value is that of vsprintf. */
static __attribute__ ((__format__ (__printf__, 2, 3))) int setproctitle(char **argv, const char *fmt, ...) {
    // https://github.com/torvalds/linux/commit/d26d0cd97c88eb1a5704b42e41ab443406807810
    // https://source.chromium.org/chromium/chromium/src/+/master:content/common/set_process_title_linux.cc

    static int argv_len = 0;
    static char **argv_saved;

    if (argv) {
        argv_saved = argv;
        for (char **x = argv_saved; *x; x++) {
            if (*x != *argv_saved + argv_len) {
                // next arg is not consecutive, so stop here
                break;
            }
            argv_len += strlen(*x) + 1;
        }
    }
    if (!fmt) {
        return argv_len;
    }
    if (!argv_len) {
        return -1;
    }

    va_list a;
    va_start(a, fmt);
    int r = vsnprintf(*argv_saved, argv_len, fmt, a);
    for (char *x = *argv_saved; x < *argv_saved + argv_len; x++) {
        if (x == *argv_saved + argv_len-1) {
            *x = '.';
        } else if (x >= *argv_saved + r || x == *argv_saved + argv_len-2) {
            *x = '\0';
        }
    }
    va_end(a);
    return r;
}

/** Get the number of available logical cores. */
static int nprocs(void) {
    int c = get_nprocs_conf();
    cpu_set_t cs;
    CPU_ZERO(&cs);
    sched_getaffinity(0, sizeof(cs), &cs);
    return CPU_COUNT(&cs) < c ? CPU_COUNT(&cs) : c;
}

static bool starts_with(const char *s, const char *p) {
    return !strncmp(s, p, strlen(p));
}

#define __NSWRAP_STATUS_RE_REGEXP(_r, _g) _r
#define NSWRAP_STATUS_RE_REGEXP NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_REGEXP, _, _)

#define __NSWRAP_STATUS_RE_GROUPS(_r, _g) do { _g } while (0)
#define NSWRAP_STATUS_RE_GROUPS(_int, _str) NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_GROUPS, _int, _str)

#define __NSWRAP_STATUS_RE_MATCHES_1(_r, _g) (1 _g)
#define __NSWRAP_STATUS_RE_MATCHES_2(_v) + 1
#define NSWRAP_STATUS_RE_MATCHES NSWRAP_STATUS_RE(__NSWRAP_STATUS_RE_MATCHES_1, __NSWRAP_STATUS_RE_MATCHES_2, __NSWRAP_STATUS_RE_MATCHES_2)

typedef enum {
    nslog_dbg,
    nslog_inf,
    nslog_wrn,
    nslog_err,
} nslog_level_t;

static struct {
    bool force_quit;
    bool quit_requested;

    struct {
        /* log level */
        nslog_level_t level;

        /* if our stdout is a tty */
        bool istty; // note: you can easily test how nswrap behaves without a tty by putting 'cat - | ' before and ' | cat -' after the command
        /* whether to use setproctitle */
        bool setproctitle;

        /* extra label to add to title */
        const char *setproctitle_extra;

        /* whether to use an external wine build */
        bool extwine;

        /* whether to ignore the watchdog */
        bool nowatchdogquit;

        /* dir with runtime files (defaults to the executable path with bin/nswrap removed) */
        char dir[1024];
    } cfg;

    struct {
        sigset_t origset;
        bool origset_ok;
        int sfd;
        int shutdown_count;
    } sig;

    struct {
        int pty_mastr_fd;
        int pty_slave_fd;
        int pty_slave_n;
        char pty_slave_fn[20];
        regex_t title_re;

        int state;
        size_t n_inp, n_tit, n_out;
        char b_inp[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE];
        char b_tit[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE + 1]; // +1 for the null terminator
        char b_out[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE * 2 + 32]; // b_inp + b_tit + room for unprocessed escapes

        size_t n_stdin, n_stdin_write; // first is buffered stdin length, second is the offset to write until (i.e., newline so line buffered)
        char b_stdin[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE];

        struct {
            char title[NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE + 1];

            bool parsed;
            char map_name[32];
            char playlist_name[32];
            int player_count;
            int max_players;
        } status;
    } io;

    struct {
        int tfd;
        struct timespec last;
    } watchdog;

    struct {
        int errno_pipe[2];
        pid_t pid;
        bool exited;
        bool reaped;
        int wstatus;
    } wine;
} state;

#define NSLOG(_level, _level_color, _fmt_color, _fmt, ...) do { \
    int saved_errno = errno; \
    if (nslog_##_level >= state.cfg.level) { \
        errno = saved_errno; \
        if (state.cfg.istty) { \
            printf("\x1b[0m" "\x1b[36m" "[nswrap] " "\x1b[" #_level_color "m" "[" #_level "] " "\x1b[%dm" _fmt "\x1b[0m" "\n", _fmt_color, ##__VA_ARGS__); \
        } else { \
            printf("[nswrap] [" #_level "] " _fmt "\n", ##__VA_ARGS__); \
        } \
        fflush(stdout); \
    } \
    errno = saved_errno; \
} while (0)

#ifdef __FILE_NAME__
#define NSLOG_DBG(fmt, ...)   NSLOG(dbg, 90, 90, "[%s:%d %s] " fmt, __FILE_NAME__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define NSLOG_DBG(fmt, ...)   NSLOG(dbg, 90, 90, "[%s:%d %s] " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#endif
#define NSLOG_INF(fmt, ...)   NSLOG(inf, 34,  0, fmt, ##__VA_ARGS__)
#define NSLOG_WRN(fmt, ...)   NSLOG(wrn, 33, 33, fmt, ##__VA_ARGS__)
#define NSLOG_WRNNO(fmt, ...) NSLOG(wrn, 33, 33, fmt ": %s", ##__VA_ARGS__, strerror(errno))
#define NSLOG_ERR(fmt, ...)   NSLOG(err, 31, 33, fmt, ##__VA_ARGS__)
#define NSLOG_ERRNO(fmt, ...) NSLOG(err, 31, 33, fmt ": %s", ##__VA_ARGS__, strerror(errno))

static void handle_watchdog_timer_trigger(void) {
    uint64_t tmp;
    if (read(state.watchdog.tfd, &tmp, sizeof(tmp)) == -1) {
        NSLOG_WRNNO("failed to read watchdog timerfd");
        return;
    }
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        NSLOG_WRNNO("failed to get current time");
    }
    if (state.watchdog.last.tv_sec) {
        NSLOG_ERR("did not receive a title update in time (%ds): last tick was %lds ago", NSWRAP_WATCHDOG_TIMEOUT, (long)(ts.tv_sec - state.watchdog.last.tv_sec));
    } else {
        NSLOG_ERR("did not receive initial title update in time (%ds)", NSWRAP_WATCHDOG_TIMEOUT_INITIAL);
    }
    if (state.cfg.nowatchdogquit) {
        NSLOG_WRN("not force-quitting since watchdog quit is disabled");
    } else {
        state.force_quit = true;
    }
}

static void maybe_update_proctitle(void) {
    if (state.cfg.setproctitle) {
        if (state.io.status.parsed) {
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
            putft(state.io.status.player_count >= 0, "?", "%d", state.io.status.player_count);
            putft(state.io.status.max_players > 0, "/?", "/%d", state.io.status.max_players);
            putft(*state.io.status.map_name, " ???", " %s", state.io.status.map_name);
            putft(*state.io.status.playlist_name, " ???", " %s", state.io.status.playlist_name);
            #undef putf
            #undef putft
            if (state.cfg.setproctitle_extra && *state.cfg.setproctitle_extra) {
                setproctitle(NULL, "northstar %s [%s]", state.cfg.setproctitle_extra, buf);
            } else {
                setproctitle(NULL, "northstar [%s]", buf);
            }
        } else {
            if (state.cfg.setproctitle_extra && *state.cfg.setproctitle_extra) {
                setproctitle(NULL, "northstar %s", state.cfg.setproctitle_extra);
            } else {
                setproctitle(NULL, "northstar");
            }
        }
    }
}

static void poke_watchdog(void) {
    if (clock_gettime(CLOCK_MONOTONIC, &state.watchdog.last) == -1) {
        NSLOG_WRNNO("failed to update watchdog time");
    }
    if (timerfd_settime(state.watchdog.tfd, 0, &(struct itimerspec){
        .it_value.tv_sec = NSWRAP_WATCHDOG_TIMEOUT,
    }, NULL) == -1) {
        NSLOG_WRNNO("failed to update watchdog timeout");
    }
}

static void handle_title_update(void) {
    regmatch_t m[NSWRAP_STATUS_RE_MATCHES];
    int rc;
    if ((rc = regexec(&state.io.title_re, state.io.status.title, NSWRAP_STATUS_RE_MATCHES, m, 0))) {
        if (rc != REG_NOMATCH) {
            char err[512];
            regerror(rc, &state.io.title_re, err, sizeof(err));
            NSLOG_ERRNO("failed to match title regex: %s", err);
        }
        state.io.status.parsed = false;
    } else {
        int i = 0;
        #define m_str(_v) \
            i++; snprintf(state.io.status._v, sizeof(state.io.status._v), "%.*s", (int)(m[i].rm_eo - m[i].rm_so), state.io.status.title + m[i].rm_so);
        #define m_int(_v) \
            i++; state.io.status._v = 0; for (regoff_t j = m[i].rm_so; j < m[i].rm_eo; j++) { state.io.status._v = 10 * state.io.status._v + (state.io.status.title[j] - '0'); };
        NSWRAP_STATUS_RE_GROUPS(m_int, m_str);
        #undef m_str
        #undef m_int
        state.io.status.parsed = true;
    }
    if (state.io.status.parsed) {
        NSLOG_DBG("parsed status update (title: %s)", state.io.status.title);
        poke_watchdog();
        maybe_update_proctitle();
    }
}

static void handle_io_master_readable(void) {
    ssize_t tmp;
    if ((tmp = read(state.io.pty_mastr_fd, state.io.b_inp, sizeof(state.io.b_inp))) == -1) {
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            NSLOG_WRNNO("failed to read output pty");
        }
        return;
    }
    state.io.n_inp = (size_t)(tmp); // note: not EPOLLET, so we don't need to read it all at once; it'll just be triggered again later

    // fast path when no escape sequences in the buffer
    if (state.io.state == 0) {
        for (size_t i = 0; i < state.io.n_inp; i++) {
            if (state.io.b_inp[i] == 0x1B) {
                goto slow;
            }
        }
        write(STDOUT_FILENO, state.io.b_inp, state.io.n_inp);
        fdatasync(STDOUT_FILENO);
        return;
    }

slow:
    state.io.n_out = 0;
    for (size_t i = 0; i < state.io.n_inp; i++) {
        char c = state.io.b_inp[i];
        switch (state.io.state) {
        case 0: // normal output
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = c;
                break;
            case 0x1B:
                state.io.state = 1;
                break;
            }
            break;
        case 1: // at \x1B
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = c;
                break;
            case ']':
                state.io.state = 2;
                break;
            case '[':
                state.io.state = 12;
                break;
            }
            break;
        case 2: // at \x1B]
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = ']';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case '0':
                state.io.state = 3;
                break;
            }
            break;
        case 3: // at \x1B]0
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = ']';
                state.io.b_out[state.io.n_out++] = '0';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case ';':
                if (NSWRAP_IOPROC_TTY_TITLE && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = 0x1B;
                    state.io.b_out[state.io.n_out++] = ']';
                    state.io.b_out[state.io.n_out++] = '0';
                    state.io.b_out[state.io.n_out++] = c;
                }
                state.io.state = 4;
                state.io.n_tit = 0;
                break;
            }
            break;
        case 4: // in \x1B]0;
            switch (c) {
            default:
                if (NSWRAP_IOPROC_TTY_TITLE && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = c;
                }
                // next title char
                if (state.io.n_tit < NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE) {
                    state.io.b_tit[state.io.n_tit++] = c;
                    break;
                }
                __attribute__((fallthrough));
            case 0x07:
                if (NSWRAP_IOPROC_TTY_TITLE && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = c;
                }
                // end of title || overflow
                if (state.io.n_tit == NSWRAP_IOPROC_OUTPUT_CHUNK_SIZE) {
                    state.io.state = 5;
                } else {
                    state.io.state = 0;
                }
                memcpy(state.io.status.title, state.io.b_tit, state.io.n_tit);
                state.io.status.title[state.io.n_tit] = '\0';
                handle_title_update();
                state.io.n_tit = 0;
                break;
            case 0x1B:
                // start of a new escape sequence (this shouldn't happen)
                state.io.state = 1;
                break;
            }
            break;
        case 5: // in title
            switch (c) {
            default:
                if (NSWRAP_IOPROC_TTY_TITLE && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = c;
                }
                // overflowing title character
                break;
            case 0x07:
                if (NSWRAP_IOPROC_TTY_TITLE && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = c;
                }
                // end of the overflowing title
                state.io.state = 0;
                break;
            case 0x1B:
                if (NSWRAP_IOPROC_TTY_TITLE && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = 0x07; // end the title
                }
                // start of a new escape sequence (this shouldn't happen)
                state.io.state = 1;
                break;
            }
            break;
        case 12: // at \x1B[
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = '[';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case '?':
                state.io.state = 13;
                break;
            case '1':
                state.io.state = 23;
                break;
            case 'm': // text attr: end
                state.io.state = 0;
                break;
            case '3': // text attr: foreground
            case '4': // text attr: background
            case '9': // text attr: foreground light
                if (NSWRAP_IOPROC_TTY_COLOR && state.cfg.istty) {
                    state.io.b_out[state.io.n_out++] = 0x1B;
                    state.io.b_out[state.io.n_out++] = '[';
                    state.io.b_out[state.io.n_out++] = c;
                }
                state.io.state = 33;
                break;
            case 'K':
                // ignore the CR equivalent
                state.io.state = 0;
                break;
            }
            break;
        case 13: // at \x1B[?
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = '[';
                state.io.b_out[state.io.n_out++] = '?';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case '2':
                state.io.state = 14;
                break;
            }
            break;
        case 14: // at \x1B[?2
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = '[';
                state.io.b_out[state.io.n_out++] = '?';
                state.io.b_out[state.io.n_out++] = '2';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case '5':
                state.io.state = 15;
                break;
            }
            break;
        case 15: // at \x1B[?25
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = '[';
                state.io.b_out[state.io.n_out++] = '?';
                state.io.b_out[state.io.n_out++] = '2';
                state.io.b_out[state.io.n_out++] = '5';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case 'l':
                // ignore hide cursor
                state.io.state = 0;
                break;
            case 'h':
                // ignore show cursor
                state.io.state = 0;
                break;
            }
            break;
        case 23: // at \x1B[1
            switch (c) {
            default:
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = 0x1B;
                state.io.b_out[state.io.n_out++] = '[';
                state.io.b_out[state.io.n_out++] = '1';
                state.io.b_out[state.io.n_out++] = c;
                break;
            case 'C':
                // move cursor right 1
                state.io.state = 0;
                state.io.b_out[state.io.n_out++] = ' ';
                break;
            }
            break;
        case 33: // inside text attributes (i.e., ignore anything until an invalid attr char or an 'm' to terminate it)
            if (NSWRAP_IOPROC_TTY_COLOR && state.cfg.istty) {
                state.io.b_out[state.io.n_out++] = c;
            }
            if (c == ';')
                break; // separator
            if (c >= '0' && c <= '9')
                break; // attribute
            if (c != 'm')
                state.io.b_out[state.io.n_out++] = c; // invalid char, so output it
            state.io.state = 0;
            break;
        }
    }
    if (state.io.n_out) {
        write(STDOUT_FILENO, state.io.b_out, state.io.n_out);
        fdatasync(STDOUT_FILENO);
    }
    return;
}

static void handle_io_master_writable(void) {
    if (!state.io.n_stdin_write) {
        // shouldn't hit this since we only poll for writable if we have something in the buffer
        NSLOG_WRN("poll returned for pty master writable, but nothing to write");
        return;
    }
    if (state.io.n_stdin_write > state.io.n_stdin) {
        NSLOG_ERR("wtf: state.io.n_stdin_write > state.io.n_stdin");
        state.io.n_stdin = state.io.n_stdin_write = 0;
        return;
    }

    NSLOG_DBG("writing up to %zu/%zu buffered stdin bytes to pty master", state.io.n_stdin_write, state.io.n_stdin);
    ssize_t n = write(state.io.pty_mastr_fd, state.io.b_stdin, state.io.n_stdin_write);
    if (n == -1) {
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            NSLOG_WRNNO("failed to write buffered stdin to pty master");
        }
        return;
    }
    NSLOG_DBG("wrote %zd bytes", n);

    if ((size_t)(n) < state.io.n_stdin_write) {
        state.io.n_stdin -= n;
        state.io.n_stdin_write -= n;
        memmove(state.io.b_stdin, &state.io.b_stdin[n], state.io.n_stdin_write);
    } else  {
        state.io.n_stdin = 0;
        state.io.n_stdin_write = 0;
    }
}

static void handle_io_stdin_readable(void) {
    if (state.io.n_stdin == sizeof(state.io.b_stdin)) {
        if (state.io.n_stdin_write && state.io.n_stdin > state.io.n_stdin_write) {
            NSLOG_WRN("stdin buffer overflow; discarding oldest line (%zu bytes)", state.io.n_stdin_write);
            memmove(state.io.b_stdin, &state.io.b_stdin[state.io.n_stdin_write], state.io.n_stdin - state.io.n_stdin_write);
            state.io.n_stdin -= state.io.n_stdin_write;
        } else {
            NSLOG_WRN("stdin buffer overflow; discarding oldest %zu bytes", state.io.n_stdin_write);
            state.io.n_stdin = 0;
        }
        state.io.n_stdin_write = 0;
    }

    NSLOG_DBG("stdin readable; reading up to %zu bytes", sizeof(state.io.b_stdin) - state.io.n_stdin);
    ssize_t n = read(STDIN_FILENO, &state.io.b_stdin[state.io.n_stdin], sizeof(state.io.b_stdin) - state.io.n_stdin);
    if (n == -1) {
        if (errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) {
            NSLOG_WRNNO("failed to read stdin to buffer");
        }
        return;
    }
    state.io.n_stdin += n;
    NSLOG_DBG("read %zd bytes\n", n);

    // find offset of the last line terminator
    for (ssize_t i = state.io.n_stdin-1; i >= 0; i--) {
        if (state.io.b_stdin[i] == '\n') {
            state.io.b_stdin[i] = '\r'; // pty terminates lines with CR
        }
        if (i == 0 || state.io.b_stdin[i] == '\r') {
            state.io.n_stdin_write = i+1;
            break;
        }
    }
    if (state.io.n_stdin_write) {
        NSLOG_DBG("queuing pty master write of %zu bytes from stdin", state.io.n_stdin_write);
    }
}

static void please_quit(void) {
    const char *cmd = "\rquit\r";
    memcpy(state.io.b_stdin, cmd, strlen(cmd));
    state.io.n_stdin = state.io.n_stdin_write = strlen(cmd);
    state.quit_requested = true;
    NSLOG_INF("requesting server quit");
}

static void handle_sig_chld(void) {
    for (;;) {
        int wstatus;
        pid_t rc = waitpid(-1, &wstatus, WNOHANG);
        if (rc == -1) {
            if (errno == ECHILD) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (rc != 0) {
            if (rc == state.wine.pid) {
                NSLOG_DBG("handled sigchld for wine process");
                state.wine.exited = true;
                state.wine.reaped = true;
                state.wine.wstatus = wstatus;
            }
            NSLOG_INF("child %d exited", (int)(rc));
        }
        break;
    }
}

static void handle_sig_shutdown(void) {
    switch (state.sig.shutdown_count++) {
    case 0:
        NSLOG_INF("received first shutdown signal, requesting game server exit");
        please_quit();
        break;
    case 1:
        NSLOG_INF("received second shutdown signal, terminating wine");
        if (!state.wine.exited) {
            if (kill(state.wine.pid, SIGTERM) == -1) {
                NSLOG_ERRNO("failed to kill wine (pid=%d)", (int)(state.wine.pid));
            }
        }
        break;
    case 2:
        NSLOG_INF("received third shutdown signal, killing wine");
        if (!state.wine.exited) {
            if (kill(state.wine.pid, SIGKILL) == -1) {
                NSLOG_ERRNO("failed to kill wine (pid=%d)", (int)(state.wine.pid));
            }
        }
        break;
    case 3:
        NSLOG_INF("received third shutdown signal, forcefully terminating");
        state.force_quit = true;
        break;
    }
}

int main(int argc, char **argv) {
    state.cfg.istty = isatty(STDOUT_FILENO); // whether we'll write ansi escapes to stdout, etc
    state.cfg.level = strcmp(getenv("NSWRAP_DEBUG") ?: "", "1") ? nslog_inf : nslog_dbg; // whether to show debug logs
    state.cfg.setproctitle = strcmp(getenv("NSWRAP_NOPROCTITLE") ?: "", "1"); // don't update the process title
    state.cfg.setproctitle_extra = getenv("NSWRAP_INSTANCE"); // set an instance name for the process title
    state.cfg.extwine = !strcmp(getenv("NSWRAP_EXTWINE") ?: "", "1"); // whether to use the system wine (from PATH and the WINE* env vars) instead of the built-in one
    state.cfg.nowatchdogquit = !strcmp(getenv("NSWRAP_NOWATCHDOGQUIT") ?: "", "1"); // don't force-quit on watchdog trigger

    /* get runtime dir */
    if (getenv("NSWRAP_RUNTIME")) {
        ssize_t n = snprintf(state.cfg.dir, sizeof(state.cfg.dir), "%s", getenv("NSWRAP_RUNTIME"));
        if (n == -1 || n == sizeof(state.cfg.dir)) {
            NSLOG_ERR("runtime dir (%s) is too long", getenv("NSWRAP_RUNTIME"));
            goto cleanup;
        }
    } else {
        ssize_t n = readlink("/proc/self/exe", state.cfg.dir, sizeof(state.cfg.dir)-1);
        if (n == sizeof(state.cfg.dir)) {
            n = -1;
            errno = ENAMETOOLONG;
        }
        if (n == -1) {
            NSLOG_ERRNO("failed to get own executable path");
            goto cleanup;
        }
        state.cfg.dir[n] = '\0';
        if (*state.cfg.dir != '/') {
            NSLOG_ERR("own executable path %s is not absolute", state.cfg.dir);
            goto cleanup;
        }
        if (strcmp(&state.cfg.dir[n-sizeof("/bin/nswrap")+1], "/bin/nswrap")) {
            NSLOG_ERR("own executable path %s does not end in /bin/nswrap (override the runtime base dir with NSWRAP_RUNTIME)", state.cfg.dir);
            goto cleanup;
        } else {
            state.cfg.dir[n-sizeof("/bin/nswrap")+1] = '\0';
        }
        setenv("NSWRAP_RUNTIME", state.cfg.dir, 1);
    }

    /* validate runtime dir */
    {
        if (*state.cfg.dir != '/') {
            NSLOG_ERR("runtime dir (%s) must be an absolute path", state.cfg.dir);
            goto cleanup;
        }
        struct stat statbuf;
        if (stat(state.cfg.dir, &statbuf) == -1) {
            NSLOG_ERRNO("cannot access runtime dir (%s)", state.cfg.dir);
            goto cleanup;
        }
        if (!S_ISDIR(statbuf.st_mode)) {
            NSLOG_ERR("runtime dir (%s) must be a dir", state.cfg.dir);
            goto cleanup;
        }
        if (!state.cfg.extwine) {
            char tmp[sizeof(state.cfg.dir)*2];
            snprintf(tmp, sizeof(tmp), "%s/bin/wine64", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/wine64' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/bin/wine64-preloader", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/wine64-preloader' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/bin/wineserver", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/wineserver' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/lib64/wine/x86_64-unix", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine lib dir 'lib64/wine/x86_64-unix' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/lib64/wine/x86_64-windows", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine lib dir 'lib64/wine/x86_64-windows' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/prefix", state.cfg.dir);
            if (access(tmp, R_OK|W_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain writable wineprefix directory 'prefix' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            #ifdef __aarch64__
            snprintf(tmp, sizeof(tmp), "%s/bin/box64/box64", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/box64/box64' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/bin/box64/wine64", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/box64/wine64' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/bin/box64/wine64-preloader", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/box64/wine64-preloader' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            snprintf(tmp, sizeof(tmp), "%s/bin/box64/wineserver", state.cfg.dir);
            if (access(tmp, R_OK|X_OK) == -1) {
                NSLOG_ERRNO("runtime dir must contain wine executable 'bin/box64/wineserver' (%s) unless NSWRAP_EXTWINE is set", tmp);
                goto cleanup;
            }
            #endif
        }
    }

    /* arguments, setproctitle */
    {
        const char *dummy_arg = "                                                ";
        if (argc > 1 && !strcmp(argv[1], "-dedicated")) {
            if (state.cfg.setproctitle) {
                char *old = argv[1];
                argv[1] = strdupa(dummy_arg); // this is fine since this will only live up to the execve below, or will be restored
                NSLOG_DBG("re-execing with space in argv");
                extern char **environ;
                if (execve("/proc/self/exe", argv, environ) == -1) {
                    NSLOG_WRNNO("failed to self-exec with additional space in argv for process title failed: execve\n");
                }
                argv[1] = old;
            }
        } else if (!state.cfg.setproctitle || argc <= 1 || strcmp(argv[1], dummy_arg)) {
            NSLOG_ERR("first argument must be -dedicated");
            exit(2);
        }
        if (state.cfg.setproctitle) {
            setproctitle(argv, NULL);
        }
    }

    /* valid current dir */
    if (access("NorthstarLauncher.exe", F_OK)) {
        char tmp[1024];
        NSLOG_ERR("NorthstarLauncher.exe does not exist in the current directory (%s)", getcwd(tmp, sizeof(tmp)) ?: "?");
        goto cleanup;
    }

    /* info */
    {
        NSLOG_INF("nswrap v2");
        NSLOG_INF("%s", state.cfg.dir);
        NSLOG_INF("");

        NSLOG_INF("config:");
        NSLOG_INF("- log level %d", state.cfg.level);
        NSLOG_INF("- stdin %s a tty (%s use color, %s accept console title updates)",
            state.cfg.istty ? "is" : "is not",
            (state.cfg.istty && NSWRAP_IOPROC_TTY_COLOR) ? "will" : "will not",
            (state.cfg.istty && NSWRAP_IOPROC_TTY_TITLE) ? "will" : "will not");
        NSLOG_INF("- %s update process name (instance label: %s)",
            state.cfg.setproctitle ? "will" : "will not", state.cfg.setproctitle_extra ?: "none");
        NSLOG_INF("- using %s wine64", state.cfg.extwine ? "external" : "built-in");
        NSLOG_INF("- using watchdog initial=%ds interval=%ds no_exit=%s", NSWRAP_WATCHDOG_TIMEOUT_INITIAL, NSWRAP_WATCHDOG_TIMEOUT, state.cfg.nowatchdogquit ? "yes" : "no");
        NSLOG_INF("- using watchdog title regexp: %s", NSWRAP_STATUS_RE_REGEXP);
        NSLOG_INF("");

        int np = nprocs();
        struct sysinfo sinfo;
        struct utsname uinfo;
        if (sysinfo(&sinfo) == -1) {
            NSLOG_WRN("failed to get sysinfo");
        } else if (uname(&uinfo) == -1) {
            NSLOG_WRN("failed to get uname");
        } else {
            NSLOG_INF("sysinfo:");
            NSLOG_INF("- kernel: %s %s %s %s %s", uinfo.sysname, uinfo.nodename, uinfo.release, uinfo.version, uinfo.machine);
            NSLOG_INF("- processor: %d cores", np);
            NSLOG_INF("- memory: %ld total, %ld free, %ld shared, %ld buffer", sinfo.totalram*sinfo.mem_unit, sinfo.freeram*sinfo.mem_unit, sinfo.sharedram*sinfo.mem_unit, sinfo.bufferram*sinfo.mem_unit);
            NSLOG_INF("- swap: %ld total, %ld free", sinfo.totalswap*sinfo.mem_unit, sinfo.freeswap*sinfo.mem_unit);
            NSLOG_INF("");
        }

        #ifdef __aarch64__
        NSLOG_WRN("arm64:");
        NSLOG_WRN("- arm64 support is experimental");
        NSLOG_WRN("- many arm64 devices, including Raspberry Pis are too slow, and will cause performance issues");
        NSLOG_WRN("- testing has been primarily done on Ampere-based arm64 cloud instances");
        NSLOG_WRN("- memory usage will be higher");
        NSLOG_WRN("- northstar may hang during startup (if it does, restart it)");
        NSLOG_WRN("- usage with external wine builds will almost certainly not work");
        NSLOG_WRN("- your host needs to be glibc-based, just like with the regular version");
        NSLOG_WRN("- box64 env vars will be passed through and override nswrap's defaults");
        NSLOG_WRN("- the other wine processes don't exit properly under box64 (in docker, this shouldn't matter; if standalone, you can leave them around or kill them manually)");
        NSLOG_WRN("- this is unsupported");
        NSLOG_WRN("- this may change at any time");
        NSLOG_WRN("- use it at your own risk");
        NSLOG_WRN("- you have been warned");
        NSLOG_WRN("");
        #endif
    }

    /* signals */
    {
        NSLOG_DBG("setting up signal handlers");
        if (sigprocmask(0, NULL, &state.sig.origset) == -1) {
            NSLOG_ERRNO("sigprocmask get");
            goto cleanup;
        } else {
            state.sig.origset_ok = true;
        }
        sigset_t sigset;
        if (sigfillset(&sigset) == -1) {
            NSLOG_ERRNO("sigfillset");
            goto cleanup;
        }
        if (sigprocmask(SIG_BLOCK, &sigset, NULL)) {
            NSLOG_ERRNO("sigprocmask set block");
            goto cleanup;
        }
        if (sigemptyset(&sigset) == -1) {
            NSLOG_ERRNO("sigemptyset");
            goto cleanup;
        }
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGCHLD);
        if ((state.sig.sfd = signalfd(-1, &sigset, SFD_CLOEXEC)) < 0) {
            NSLOG_ERRNO("signalfd");
            goto cleanup;
        }
        NSLOG_DBG("signalfd %d", state.sig.sfd);
    }

    /* pty */
    {
        NSLOG_DBG("setting up pty");
        if ((state.io.pty_mastr_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC)) == -1) {
            NSLOG_ERRNO("failed to allocate pty master");
            goto cleanup;
        }
        if (ioctl(state.io.pty_mastr_fd, TIOCSPTLCK, &(int) {0}) == -1) {
            NSLOG_ERRNO("failed to unlock pty master");
            goto cleanup;
        }
        if (ioctl(state.io.pty_mastr_fd, TIOCGPTN, &state.io.pty_slave_n) == -1) {
            NSLOG_ERRNO("failed to get pty slave");
            goto cleanup;
        }
        if (snprintf(state.io.pty_slave_fn, sizeof(state.io.pty_slave_fn), "/dev/pts/%d", state.io.pty_slave_n) == -1) {
            NSLOG_ERRNO("failed to build pty slave filename");
            goto cleanup;
        }
        if ((state.io.pty_slave_fd = open(state.io.pty_slave_fn, O_RDWR | O_NOCTTY)) == -1) {
            NSLOG_ERRNO("failed to open pty slave");
            goto cleanup;
        }
        NSLOG_DBG("pty %s (master=%d slave=%d)", state.io.pty_slave_fn, state.io.pty_mastr_fd, state.io.pty_slave_fd);
        {
            struct termios pty_termios;
            if (tcgetattr(state.io.pty_slave_fd, &pty_termios)) {
                NSLOG_ERRNO("failed to get pty slave termios");
                goto cleanup;
            }
            pty_termios.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
            pty_termios.c_lflag |= IGNBRK | IGNPAR | IGNCR | IUTF8;
            pty_termios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
            pty_termios.c_cflag &= ~(CSIZE | PARENB);
            pty_termios.c_cflag |= CREAD | CS8;
            pty_termios.c_cc[VMIN] = 1;
            pty_termios.c_cc[VTIME] = 0;
            if (tcsetattr(state.io.pty_slave_fd, TCSANOW, &pty_termios)) {
                NSLOG_ERRNO("failed to set pty slave termios");
                goto cleanup;
            }
        }
        if (ioctl(state.io.pty_slave_fd, TIOCSWINSZ, &(struct winsize) {
            .ws_col = 1200, // so wine doesn't cut off lines
            .ws_row = 25,
        })) {
            NSLOG_ERRNO("failed to set pty slave winsize");
            goto cleanup;
        }
	    if (fcntl(state.io.pty_mastr_fd, F_SETFL, O_NONBLOCK) == -1) {
            NSLOG_ERRNO("failed to set pty master to nonblock");
            goto cleanup;
        }

        int rc;
        #define x(_n, _r, _g) _r
        if ((rc = regcomp(&state.io.title_re, NSWRAP_STATUS_RE_REGEXP, REG_EXTENDED) ? -1 : 0)) {
            char err[512];
            regerror(rc, &state.io.title_re, err, sizeof(err));
            NSLOG_ERR("failed to compile title regex: %s", err);
            goto cleanup;
        }
        #undef x
    }

    /* watchdog */
    {
        NSLOG_DBG("setting up watchdog (timeout: initial=%d interval=%d)", NSWRAP_WATCHDOG_TIMEOUT_INITIAL, NSWRAP_WATCHDOG_TIMEOUT);
        if ((state.watchdog.tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK)) == -1) {
            NSLOG_ERRNO("failed to create watchdog timerfd");
            goto cleanup;
        }
        if (timerfd_settime(state.watchdog.tfd, 0, &(struct itimerspec){
            .it_value.tv_sec = NSWRAP_WATCHDOG_TIMEOUT_INITIAL,
        }, NULL) == -1) {
            NSLOG_ERRNO("failed to set initial watchdog timeout");
            goto cleanup;
        }
        NSLOG_DBG("timerfd %d", state.watchdog.tfd);
    }

    /* exec */
    {
        NSLOG_DBG("starting wine");
        size_t i;
        char *wine_exe, *wine_argv[512], *wine_envp[512];

        i=0;
        wine_argv[i++] = strdup("wine64");
        wine_argv[i++] = strdup("NorthstarLauncher.exe");
        for (int j = 1; j < argc; j++) {
            /* first argument is -dedicated */
            if (i >= sizeof(wine_argv)/(sizeof(*wine_argv))) {
                NSLOG_ERR("too many arguments");
                goto cleanup;
            }
            if (j == 1) {
                wine_argv[i++] = strdup("-dedicated");
            } else {
                wine_argv[i++] = strdup(argv[j]);
            }
        }
        wine_argv[i++] = NULL;

        i=0;
        wine_envp[i++] = strdup("USER=nswrap");
        wine_envp[i++] = strdup("HOSTNAME=none");
        wine_envp[i++] = strdup(getenve("HOME") ?: "HOME=/");
        wine_envp[i++] = strdup(getenve("WINEDEBUG") ?: "WINEDEBUG=+msgbox,fixme-secur32,fixme-bcrypt,fixme-ver,err-wldap32,err-kerberos,err-ntlm");
        wine_envp[i++] = strdup("WINEARCH=win64");
        if (state.cfg.extwine) {
            wine_envp[i++] = strdup(getenve("PATH") ?: "PATH=/usr/local/bin:/usr/bin:/bin");
            if (getenve("LD_LIBRARY_PATH")) wine_envp[i++] = strdup(getenve("LD_LIBRARY_PATH"));
            if (getenve("WINEPREFIX")) wine_envp[i++] = strdup(getenve("WINEPREFIX"));
            else {
                NSLOG_ERR("since NSWRAP_EXTWINE is enabled, WINEPREFIX must be set");
                goto cleanup;
            }
            if (getenve("WINESERVER")) wine_envp[i++] = strdup(getenve("WINESERVER"));
            if (getenve("WINELOADER")) wine_envp[i++] = strdup(getenve("WINELOADER"));
            if (getenve("WINEDLLPATH")) wine_envp[i++] = strdup(getenve("WINEDLLPATH"));
            wine_exe = strdup("wine64");
        } else {
            #ifdef __aarch64__
            #define BINEXTRA "/box64"
            #else
            #define BINEXTRA ""
            #endif
            char tmp[sizeof(state.cfg.dir)*2];
            snprintf(tmp, sizeof(tmp), "PATH=%s/bin%s:/usr/bin", state.cfg.dir, BINEXTRA);
            wine_envp[i++] = strdup(tmp);
            #ifndef __aarch64__
            snprintf(tmp, sizeof(tmp), "LD_LIBRARY_PATH=%s/lib64", state.cfg.dir);
            wine_envp[i++] = strdup(tmp);
            #endif
            snprintf(tmp, sizeof(tmp), "WINEPREFIX=%s/prefix", state.cfg.dir);
            wine_envp[i++] = strdup(tmp);
            snprintf(tmp, sizeof(tmp), "WINESERVER=%s/bin%s/wineserver", state.cfg.dir, BINEXTRA);
            wine_envp[i++] = strdup(tmp);
            snprintf(tmp, sizeof(tmp), "WINELOADER=%s/bin%s/wine64", state.cfg.dir, BINEXTRA);
            wine_envp[i++] = strdup(tmp);
            snprintf(tmp, sizeof(tmp), "WINEDLLPATH=%s/lib64/wine", state.cfg.dir); // note: wine searches the x86_64-windows, x86_64-unix subdirs too
            wine_envp[i++] = strdup(tmp);
            snprintf(tmp, sizeof(tmp), "%s/bin%s/wine64", state.cfg.dir, BINEXTRA);
            wine_exe = strdup(tmp);
            #undef BINEXTRA
        }
        if (getenve("WINDELLOVERRIDES")) wine_envp[i++] = strdup(getenve("WINDELLOVERRIDES"));
        #ifdef __aarch64__
        {
            NSLOG_DBG("setting up box64 env vars");
            {
                extern char **environ;
                for (size_t j = 0; environ[j]; j++) {
                    const char *e = environ[j];
                    if (starts_with(e, "BOX64_")) {
                        wine_envp[i++] = strdup(e);
                        NSLOG_WRN("setting box64 env var at your own risk: %s", e);
                    }
                }
            }
            if (!getenve("BOX64_PREFER_EMULATED")) wine_envp[i++] = strdup("BOX64_PREFER_EMULATED=1");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_PREFER_EMULATED at your own risk... it's enabled by default in nswrap so the included libraries are used");
            if (!getenve("BOX64_PREFER_WRAPPED")) wine_envp[i++] = strdup("BOX64_PREFER_WRAPPED=0");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_PREFER_WRAPPED at your own risk... it's disabled by default in nswrap so the included libraries are used");
            if (!getenve("BOX64_DYNAREC")) wine_envp[i++] = strdup("BOX64_DYNAREC=1");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC at your own risk... it's enabled by default in nswrap since the server is unusable otherwise");
            if (!getenve("BOX64_DYNAREC_SAFEFLAGS")) wine_envp[i++] = strdup("BOX64_DYNAREC_SAFEFLAGS=1");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC_SAFEFLAGS at your own risk... it's set to 1 by default in nswrap to be safe, although BOX64_DYNAREC_SAFEFLAGS=0 probably works fine and is faster");
            if (!getenve("BOX64_DYNAREC_FORWARD")) wine_envp[i++] = strdup("BOX64_DYNAREC_FORWARD=512");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC_FORWARD at your own risk... this may impact performance");
            if (!getenve("BOX64_DYNAREC_BIGBLOCK")) wine_envp[i++] = strdup("BOX64_DYNAREC_BIGBLOCK=1");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC_BIGBLOCK at your own risk... this may impact performance");
            if (!getenve("BOX64_DYNAREC_X87DOUBLE")) wine_envp[i++] = strdup("BOX64_DYNAREC_X87DOUBLE=0");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC_X87DOUBLE at your own risk... this may impact performance");
            if (!getenve("BOX64_DYNAREC_FASTNAN")) wine_envp[i++] = strdup("BOX64_DYNAREC_FASTNAN=1");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC_FASTNAN at your own risk... this may impact performance");
            if (!getenve("BOX64_DYNAREC_FASTROUND")) wine_envp[i++] = strdup("BOX64_DYNAREC_FASTROUND=1");
            else NSLOG_WRN("you have chosen to override nswrap's BOX64_DYNAREC_FASTROUND at your own risk... this may impact performance");
        }
        #endif
        wine_envp[i++] = NULL;

        for (i = 0; wine_argv[i]; i++) {
            NSLOG_DBG("wine argv[%3zu] %s", i, wine_argv[i]);
        }
        for (i = 0; wine_envp[i]; i++) {
            NSLOG_DBG("wine envp[%3zu] %s", i, wine_envp[i]);
        }
        NSLOG_DBG("wine %s", wine_exe);

        if (pipe2(state.wine.errno_pipe, O_DIRECT | O_NONBLOCK)) {
            NSLOG_ERRNO("create errno pipe");
            goto cleanup;
        }

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            NSLOG_WRNNO("failed to set PR_SET_NO_NEW_PRIVS=1");
        }
        if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) {
            NSLOG_WRNNO("failed to set PR_SET_CHILD_SUBREAPER=1 (grandchildren may not be reaped)");
        }

        if ((state.wine.pid = fork()) == -1) {
            NSLOG_ERRNO("failed to start process: fork");
            goto cleanup;
        }
        if (state.wine.pid == 0) {
            setsid(); // separate ctty
            ioctl(state.io.pty_slave_fd, TIOCSCTTY, 1);
            dup2(state.io.pty_slave_fd, STDIN_FILENO);
            dup2(state.io.pty_slave_fd, STDOUT_FILENO);
            dup2(state.io.pty_slave_fd, STDERR_FILENO);
            close(state.io.pty_mastr_fd); // not cloexec
            close(state.io.pty_slave_fd); // already dup'd to stdin/stdout/stderr
            sigprocmask(SIG_SETMASK, &state.sig.origset, NULL);
            execvpe(wine_exe, wine_argv, wine_envp);
            const int n = errno;
            write(state.wine.errno_pipe[1], &n, sizeof(n));
            close(state.wine.errno_pipe[1]);
            _exit(127);
        }
        for (i = 0; wine_argv[i]; i++) {
            free(wine_argv[i]);
        }
        for (i = 0; wine_envp[i]; i++) {
            free(wine_envp[i]);
        }
        free(wine_exe);
        NSLOG_DBG("started wine with pid %d", (int)(state.wine.pid));
    }
    maybe_update_proctitle(); // this has to be done AFTER finishing up with argv

    enum {
        poll_master,
        poll_stdin,
        poll_signal,
        poll_errno,
        poll_watchdog,
    };
    struct pollfd poll_[] = {
        [poll_master]   = { .fd = state.io.pty_mastr_fd, .events = POLLIN },
        [poll_stdin]    = { .fd = STDIN_FILENO, .events = POLLIN },
        [poll_signal]   = { .fd = state.sig.sfd, .events = POLLIN },
        [poll_errno]    = { .fd = state.wine.errno_pipe[0], .events = POLLIN },
        [poll_watchdog] = { .fd = state.watchdog.tfd, .events = POLLIN },
    };
    while (!state.force_quit && !state.wine.exited) {
        if (state.io.n_stdin_write) {
            poll_[poll_master].events |= POLLOUT;
        } else {
            poll_[poll_master].events &= ~POLLOUT;
        }
        if (poll(poll_, sizeof(poll_)/sizeof(*poll_), -1) == -1) {
            NSLOG_ERRNO("poll failed");
            goto cleanup;
        }
        if (!state.force_quit && poll_[poll_errno].revents & POLLIN) {
            int n;
            if (read(state.wine.errno_pipe[0], &n, sizeof(n)) == -1) {
                NSLOG_ERR("failed to start wine, but we couldn't get the errno: failed to read pipe");
            } else {
                errno = n;
                NSLOG_ERRNO("failed to start wine");
            }
            goto cleanup;
        }
        if (!state.force_quit && poll_[poll_signal].revents & POLLIN) {
	        struct signalfd_siginfo siginfo;
            ssize_t n = read(state.sig.sfd, &siginfo, sizeof(siginfo));
            if (n != sizeof(siginfo)) {
                if (n < 0 && errno != EAGAIN && errno != EINTR) {
                    NSLOG_ERRNO("failed to read signal from signalfd");
                }
            } else {
                if (siginfo.ssi_signo == SIGCHLD) {
                    handle_sig_chld();
                }
                if (siginfo.ssi_signo == SIGINT || siginfo.ssi_signo == SIGQUIT || siginfo.ssi_signo == SIGTERM) {
                    handle_sig_shutdown();
                }
            }
        }
        if (!state.force_quit && poll_[poll_watchdog].revents & POLLIN) {
            handle_watchdog_timer_trigger();
        }
        if (!state.force_quit && poll_[poll_master].revents & POLLHUP) {
            NSLOG_WRN("got POLLHUP/EOF on pty master; will not be able to read logs or send concommands anymore");
            poll_[poll_master].fd = -1; // don't poll it anymore
        }
        if (!state.force_quit && poll_[poll_master].revents & POLLIN) {
            handle_io_master_readable();
        }
        if (!state.force_quit && poll_[poll_master].revents & POLLOUT) {
            handle_io_master_writable();
        }
        if (!state.force_quit && poll_[poll_stdin].revents & POLLIN) {
            handle_io_stdin_readable();
        }
        if (!state.force_quit && poll_[poll_stdin].revents & POLLHUP) {
            NSLOG_WRN("got POLLHUP/EOF on stdin; will not be able to send concommands anymore");
            poll_[poll_stdin].fd = -1; // don't poll it anymore
        }
    }
    if (state.force_quit) {
        NSLOG_WRN("force-quit requested");
    }

cleanup:
    NSLOG_INF("cleaning up");
    if (state.wine.pid) {
        if (!state.wine.exited) {
            NSLOG_INF("killing wine");
            if (kill(state.wine.pid, SIGKILL) == -1) {
                NSLOG_ERRNO("failed to kill wine (pid=%d)", (int)(state.wine.pid));
            }
        }
        if (!state.wine.reaped) {
            siginfo_t siginfo;
            if (waitid(P_PID, state.wine.pid, &siginfo, WEXITED) == -1) {
                NSLOG_WRNNO("failed to reap wine process");
            } else {
                state.wine.reaped = true;
                state.wine.wstatus = siginfo.si_status;
            }
        }
        if (state.wine.reaped) {
            if (WIFSIGNALED(state.wine.wstatus)) {
                if (state.quit_requested) {
                    NSLOG_INF("wine killed by signal %d", WTERMSIG(state.wine.wstatus));
                } else {
                    NSLOG_WRN("wine unexpectedly killed by signal %d", WTERMSIG(state.wine.wstatus));
                }
            } else {
                if (state.quit_requested) {
                    NSLOG_INF("wine exited with status %d", WEXITSTATUS(state.wine.wstatus));
                } else {
                    NSLOG_WRN("wine unexpectedly exited with status %d", WEXITSTATUS(state.wine.wstatus));
                }
            }
        }
    }
    if (state.wine.errno_pipe[0]) {
        close(state.wine.errno_pipe[0]);
    }
    if (state.wine.errno_pipe[1]) {
        close(state.wine.errno_pipe[1]);
    }
    if (state.sig.sfd) {
        close(state.sig.sfd);
    }
    if (state.sig.origset_ok) {
        sigprocmask(SIG_SETMASK, &state.sig.origset, NULL);
    }
    if (state.wine.pid) {
        bool first = false;
        struct timespec ts, tc;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        for (;;) {
            pid_t rc = waitpid(-1, NULL, WNOHANG);
            if (rc == -1) {
                if (errno == ECHILD) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                NSLOG_WRNNO("failed to wait for remaining children to exit");
                break;
            }

            if (!first) {
                first = true;
                NSLOG_INF("waiting for remaining children to exit");
            }
            if (rc == 0) {
                clock_gettime(CLOCK_MONOTONIC, &tc);
                if (tc.tv_sec - ts.tv_sec > 5) {
                    NSLOG_WRN("children did not exit in time");
                    return 1;
                }
                nanosleep(&(struct timespec){
                    .tv_nsec = 100 * 1000 * 1000,
                }, NULL);
            } else {
                NSLOG_INF("child %d exited", (int)(rc));
            }
        }
    }
    NSLOG_INF("done");
    exit(state.quit_requested ? 0 : 1);
}
