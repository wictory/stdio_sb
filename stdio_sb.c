/*
 * ISC License
 *
 * Copyright (c) 2022 Wictor Lund, Åbo Akademi University
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE

#include <sys/mount.h>

#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sched.h>

#define INITIAL_BUF_SZ ((size_t)1024)

const static char *prog_name;

static void usage()
{
    errx(1,
         "usage: %s PATH_CHROOT PATH_DATA PATH_MOUNTPOINT =PATH_OTHERS... "
         "PATH_PROG PROG_ARGS...",
         prog_name);
}

static void check_and_fixup_arg_path(const char *arg_name, char *path)
{
    int path_len;

    if (path == NULL)
        usage();

    if (*path != '/')
        errx(1, "%s does not start with '/'", arg_name);

    if (strstr(path, "..") != NULL)
        errx(1, "%s contains '..'", arg_name);

    path_len = strlen(path);

    while (path_len > 1 && path[path_len - 1] == '/')
        path[--path_len] = '\0';

    return;
}

int main(int argc, char **argv)
{
    int ret, i;
    static char *path_chroot, *path_data, *path_mountpoint, *path_prog,
        *execve_envp[1], **argv_others, **argv_execve, *buf, *buf_;
    static size_t buf_len, buf_sz;

    prog_name = argv[0];

    if (argc < 5)
        usage();

    check_and_fixup_arg_path("PATH_CHROOT", path_chroot = argv[i = 1]);
    check_and_fixup_arg_path("PATH_DATA", path_data = argv[++i]);
    check_and_fixup_arg_path("PATH_MOUNTPOINT", path_mountpoint = argv[++i]);

    argv_others = argv + ++i;

    for (; argv[i] != NULL && *argv[i] == '='; i++)
        check_and_fixup_arg_path("PATH_OTHERS", argv[i] + 1);

    check_and_fixup_arg_path("PATH_PROG", path_prog = argv[i]);
    argv_execve = argv + i;

    ret = unshare(CLONE_FS | CLONE_NEWNS | CLONE_NEWIPC);
    if (ret == -1)
        err(1, "unshare()");

    buf = malloc(buf_sz = INITIAL_BUF_SZ);
    if (buf == NULL)
        err(1, "malloc()");

    while (1) {
        buf_len = snprintf(buf, buf_sz, "%s%s", path_chroot, path_mountpoint);
        if (buf_len < buf_sz)
            break;
        buf = realloc(buf_ = buf, buf_len);
        if (buf == NULL) {
            free(buf_);
            err(1, "realloc()");
        }
    }

    ret = mount(path_data, buf, NULL, MS_BIND, NULL);

    if (ret == -1) {
        free(buf);
        err(1, "mount()");
    }

    for (i = 0; argv_others[i] != NULL && *argv_others[i] == '='; i++) {
        while (1) {
            buf_len =
                snprintf(buf, buf_sz, "%s%s", path_chroot, argv_others[i] + 1);
            if (buf_len < buf_sz)
                break;
            buf = realloc(buf_ = buf, buf_len);
            if (buf == NULL) {
                free(buf_);
                err(1, "realloc()");
            }
        }

        ret = mount(argv_others[i] + 1, buf, NULL, MS_BIND, NULL);

        if (ret == -1) {
            free(buf);
            err(1, "mount()");
        }
    }

    free(buf);

    ret = chroot(path_chroot);
    if (ret == -1)
        err(1, "chroot()");

    ret = chdir(path_mountpoint);
    if (ret == -1)
        err(1, "chdir() -> \"%s\"", path_mountpoint);

    execve_envp[0] = NULL;

    ret = execve(path_prog, argv_execve, execve_envp);

    if (ret == -1)
        err(1, "execve()");

    return 0;
}
