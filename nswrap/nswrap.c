// wayland-scanner server-header $(pkg-config --variable=pkgdatadir wayland-protocols)/stable/xdg-shell/xdg-shell.xml nswrap/xdg-shell-protocol.h
// wayland-scanner server-header $(pkg-config --variable=pkgdatadir wayland-protocols)/unstable/pointer-constraints/pointer-constraints-unstable-v1.xml nswrap/pointer-constraints-unstable-v1-protocol.h
// gcc -Wall -Wextra -Inswrap $(pkg-config --cflags --libs pixman-1 'wlroots >= 0.16.0' wayland-server) nswrap/nswrap.c 

#define WLR_USE_UNSTABLE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static struct {
    struct {
        const char                             *socket;
        struct wl_display                      *display;
        struct wlr_backend                     *backend;
        struct wlr_renderer                    *renderer;
        struct wlr_compositor                  *compositor;
        struct wlr_subcompositor               *subcompositor;
        struct wlr_pointer_constraints_v1      *pointer_constraints_v1;
        struct wlr_relative_pointer_manager_v1 *relative_pointer_manager_v1;
        struct wlr_xdg_shell                   *xdg_shell;
    } wl;
} state;

static int do_sigint(int signal_number, void *data) {
    wlr_log(WLR_ERROR, "sigint");
    wl_display_terminate(state.wl.display);
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
    wl_event_loop_add_signal(loop, SIGINT, do_sigint, NULL);
    wl_display_run(state.wl.display);

cleanup:
    // wayland
    {
        if (state.wl.display) {
            wl_display_destroy(state.wl.display); // note: this includes most other objects attached to the display
        }
        if (state.wl.renderer) {
            wlr_renderer_destroy(state.wl.renderer);
        }
    }
    return 1;
}
