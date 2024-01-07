/**
 * A shim for executing binaries with box64 without binfmt_misc.
 *
 * Box64 imposes a few requirements on us:
 * - box64 itself must be in the PATH
 * - the binary being executed must be in the BOX64_PATH
 * - libraries for that binary must be in the BOX64_LD_LIBRARY_PATH
 *
 * For the most logical behaviour, we prepend our runtime dirs to those env
 * vars, then exec box64.
 *
 * Note that if an external wine is used with nswrap, the user has to handle
 * box64 stuff themselves (with binfmt_misc or their own wrappers).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SHIM_BINARY
#error SHIM_BINARY must be defined
#endif
#define SHIM_BINARY___(x) #x
#define SHIM_BINARY__(x) SHIM_BINARY___(x)
#define SHIM_BINARY_ SHIM_BINARY__(SHIM_BINARY)

static bool starts_with(const char *s, const char *p) {
    return !strncmp(s, p, strlen(p));
}

int main(int argc, char **argv) {
    char dir[1024];
    ssize_t n = readlink("/proc/self/exe", dir, sizeof(dir)-1);
    if (n == sizeof(dir)) {
        n = -1;
        errno = ENAMETOOLONG;
    }
    if (n == -1) {
        fprintf(stderr, "nswrap-box64-shim(%s): failed to get own executable path: %s\n", SHIM_BINARY_, strerror(errno));
        exit(127);
    }
    dir[n] = '\0';

    if (*dir != '/') {
        fprintf(stderr, "nswrap-box64-shim(%s): own executable path (%s) is not absolute\n", SHIM_BINARY_, dir);
        exit(127);
    }
    if (strcmp(&dir[n-sizeof("/bin/box64/" SHIM_BINARY_)+1], "/bin/box64/" SHIM_BINARY_)) {
        fprintf(stderr, "nswrap-box64-shim(%s): own executable path (%s) does not end in /bin/box64/%s\n", SHIM_BINARY_, SHIM_BINARY_, dir);
        exit(127);
    } else {
        dir[n-sizeof("/bin/box64/" SHIM_BINARY_)+1] = '\0';
    }

    char *executable;
    if (asprintf(&executable, "%s/bin/box64/box64", dir) == -1) {
        fprintf(stderr, "nswrap-box64-shim(%s): failed to build executable path: %s\n", SHIM_BINARY_, strerror(errno));
        exit(127);
    }
    if (access(executable, R_OK|X_OK) == -1) {
        fprintf(stderr, "nswrap-box64-shim(%s): executable (%s) is not r+x: %s\n", SHIM_BINARY_, executable, strerror(errno));
        exit(127);
    }

    char *binary;
    if (asprintf(&binary, "%s/bin/%s", dir, SHIM_BINARY_) == -1) {
        fprintf(stderr, "nswrap-box64-shim(%s): failed to build binary path: %s\n", SHIM_BINARY_, strerror(errno));
        exit(127);
    }
    if (access(binary, R_OK|X_OK) == -1) {
        fprintf(stderr, "nswrap-box64-shim(%s): binary (%s) is not r+x: %s\n", SHIM_BINARY_, binary, strerror(errno));
        exit(127);
    }

    size_t arguments_n = 0;
    char **arguments = calloc(argc + 1 + 1, sizeof(char*));
    if (!arguments) {
        fprintf(stderr, "nswrap-box64-shim(%s): failed to build arguments: %s\n", SHIM_BINARY_, strerror(errno));
        exit(127);
    }
    arguments[arguments_n++] = "box64";
    arguments[arguments_n++] = SHIM_BINARY_;
    for (int j = 1; j < argc; j++) {
        arguments[arguments_n++] = argv[j];
    }

    int envc = 0;
    extern char **environ;
    for (char **v = environ; *v; v++) {
        if (!starts_with(*v, "PATH=") && !starts_with(*v, "BOX64_PATH") && !starts_with(*v, "BOX64_LD_LIBRARY_PATH")) {
            envc++;
        }
    }

    #define prepend_path_list(ptr, var, fmt, ...) do { \
        const char *val = getenv(var); \
        int r = (val && *val) \
            ? asprintf(ptr, "%s=" fmt ":%s", var, ##__VA_ARGS__, val) \
            : asprintf(ptr, "%s=" fmt, var, ##__VA_ARGS__); \
        if (r == -1) { \
            fprintf(stderr, "nswrap-box64-shim(%s): failed to build environment value: %s\n", SHIM_BINARY_, strerror(errno)); \
            exit(127); \
        } \
    } while (0)

    size_t environment_n = 0;
    char **environment = calloc(envc + 3 + 1, sizeof(char*));
    if (!environment) {
        fprintf(stderr, "nswrap-box64-shim(%s): failed to build environment: %s\n", SHIM_BINARY_, strerror(errno));
        exit(127);
    }
    prepend_path_list(&environment[environment_n], "PATH", "%s/bin/box64", dir); environment_n++;
    prepend_path_list(&environment[environment_n], "BOX64_PATH", "%s/bin", dir); environment_n++;
    prepend_path_list(&environment[environment_n], "BOX64_LD_LIBRARY_PATH", "%s/lib64", dir); environment_n++;
    for (char **v = environ; *v; v++) {
        if (!starts_with(*v, "PATH=") && !starts_with(*v, "BOX64_PATH") && !starts_with(*v, "BOX64_LD_LIBRARY_PATH")) {
            environment[environment_n++] = *v;
        }
    }

    if (execvpe(executable, arguments, environment) == -1) {
        fprintf(stderr, "nswrap-box64-shim(%s): execve failed: %s\n", SHIM_BINARY_, strerror(errno));
        exit(127);
    }
}
