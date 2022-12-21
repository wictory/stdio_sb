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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sched.h>

#define INITIAL_BUF_SZ ((size_t)1024)

#define DEFAULT_UNSHARE_FLAGS                                                  \
    ((int)(CLONE_FS | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWNET))

#define BIND_MOUNT_FREE_NONE (0x00)
#define BIND_MOUNT_FREE_SRC (0x01)
#define BIND_MOUNT_FREE_TARGET (0x02)
#define BIND_MOUNT_FREE_BOTH (BIND_MOUNT_FREE_SRC | BIND_MOUNT_FREE_TARGET)

#define USAGE_PRINT_EXTENDED (-1)
#define USAGE_PRINT_BASIC (0)

#define PROG_EXIT_STATUS_ERR (1)
#define PROG_EXIT_STATUS_OK (0)

static const char *prog_name;

static const char *
prog_name_last_component()
{
    const char *ret;

    ret = rindex(prog_name, '/');

    return ret == NULL ? prog_name : ret + 1;
}

noreturn static void
usage(int print_mode, int exit_status, const char *msg, ...)
{
    const char *prog_name_;
    va_list ap;
    int i;
    static const char *flag_doc[] = {
        "-F,-f",
        "Disable/enable CLONE_FS flag to unshare()",
        "-C,-c",
        "Disable/enable CLONE_CGROUP flag to unshare()",
        "-I,-i",
        "Disable/enable CLONE_NEWIPC flag to unshare()",
        "-N,-n",
        "Disable/enable CLONE_NEWNET flag to unshare()",
        "-U,-u",
        "Disable/enable CLONE_NEWUSER flag to unshare()",
        "-T,-t",
        "Disable/enable CLONE_NEWUTS flag to unshare(), i.e. \"hostname\" "
        "namespace",
        "-V,-v",
        "Disable/enable CLONE_SYSVSEM flag to unshare()",
        NULL};
    prog_name_ = prog_name_last_component();
    if (msg != NULL) {
        fprintf(stderr, "%s: %s", prog_name_,
                exit_status == PROG_EXIT_STATUS_OK ? "" : "error: ");
        va_start(ap, msg);
        vfprintf(stderr, msg, ap);
        va_end(ap);
        fprintf(stderr, "\n");
    }
    fprintf(stderr,
            "%s: usage: %s [-FfCcIiNnUuTtVvdh] PATH_CHROOT PATH_DATA "
            "PATH_MOUNTPOINT =PATH_OTHERS... PATH_PROG PROG_ARGS...\n",
            prog_name_, prog_name);
    if (print_mode == USAGE_PRINT_EXTENDED) {
        i = 0;
        while (flag_doc[i] != NULL) {
            fprintf(stderr, "\t%s\t%s\n", flag_doc[i], flag_doc[i + 1]);
            i += 2;
        }
        fprintf(stderr, "\t-d\tPrint debug messages\n");
        fprintf(stderr, "\t-h\tShow this message and exit\n");
    }
    exit(exit_status);
}

static void
check_and_fixup_arg_path(const char *arg_name, char *path)
{
    int path_len;

    if (path == NULL)
        usage(USAGE_PRINT_BASIC, PROG_EXIT_STATUS_ERR, NULL);

    if (*path != '/')
        errx(1, "%s does not start with '/'", arg_name);

    if (strstr(path, "..") != NULL)
        errx(1, "%s contains '..'", arg_name);

    path_len = strlen(path);

    while (path_len > 1 && path[path_len - 1] == '/')
        path[--path_len] = '\0';

    return;
}

static int
concatenate_paths_into_buf(char **buf_p, size_t *buf_sz_p, const char *path1,
                           const char *path2)
{
    int buf_len;
    char *buf;

    while (1) {
        buf_len = snprintf(*buf_p, *buf_sz_p, "%s%s", path1, path2);
        if (buf_len < *buf_sz_p)
            return buf_len < 0 ? -1 : buf_len;
        *buf_p = realloc(buf = *buf_p, buf_len);
        if (*buf_p == NULL) {
            *buf_p = buf;
            return -1;
        } else
            *buf_sz_p = buf_len;
    }
}

static void
bind_mount(char *path_src, char *path_target, int free_paths)
{
    int ret;

    ret = mount(path_src, path_target, NULL, MS_BIND, NULL);

    if (ret == 0)
        return;

    fprintf(stderr, "%s: mount() bind %s to %s: %s\n",
            prog_name_last_component(), path_src, path_target, strerror(errno));

    if (free_paths & BIND_MOUNT_FREE_SRC)
        free(path_src);

    if (free_paths & BIND_MOUNT_FREE_TARGET)
        free(path_target);

    exit(1);
}

int
main(int argc, char **argv)
{
    int i, ch;
    static char *path_chroot, *path_data, *path_mountpoint, *path_prog,
        *execve_envp[1], **argv_others, **argv_execve, *buf, *buf_;
    static size_t buf_len, buf_sz;

    static int unshare_flags = DEFAULT_UNSHARE_FLAGS, debug_flag = 0;

    prog_name = argv[0];

    while ((ch = getopt(argc, argv, "FfCcIiNnUuTtVvdh")) != -1) {
        switch (ch) {
        case 'F':
        case 'f':
            i = CLONE_FS;
            break;
        case 'C':
        case 'c':
            i = CLONE_NEWCGROUP;
            break;
        case 'I':
        case 'i':
            i = CLONE_NEWIPC;
            break;
        case 'N':
        case 'n':
            i = CLONE_NEWNET;
            break;
        case 'U':
        case 'u':
            i = CLONE_NEWUSER;
            break;
        case 'T':
        case 't':
            i = CLONE_NEWUTS;
            break;
        case 'V':
        case 'v':
            i = CLONE_SYSVSEM;
            break;
        case 'h':
            usage(USAGE_PRINT_EXTENDED, PROG_EXIT_STATUS_OK, NULL);
            continue;
        case 'd':
            debug_flag = 1;
            continue;
        default:
            usage(USAGE_PRINT_BASIC, PROG_EXIT_STATUS_ERR,
                  "invalid command-line flag");
            break;
        }
        if (isupper(ch))
            unshare_flags &= ~i;
        else if (islower(ch))
            unshare_flags |= i;
    }

    argc -= optind;
    argv += optind;

    if (argc < 5)
        usage(USAGE_PRINT_BASIC, PROG_EXIT_STATUS_ERR,
              "too few command-line arguments, is %i, should be 5", argc);

    check_and_fixup_arg_path("PATH_CHROOT", path_chroot = argv[i = 0]);
    check_and_fixup_arg_path("PATH_DATA", path_data = argv[++i]);
    check_and_fixup_arg_path("PATH_MOUNTPOINT", path_mountpoint = argv[++i]);

    argv_others = argv + ++i;

    for (; argv[i] != NULL && *argv[i] == '='; i++)
        check_and_fixup_arg_path("PATH_OTHERS", argv[i] + 1);

    check_and_fixup_arg_path("PATH_PROG", path_prog = argv[i]);
    argv_execve = argv + i;

    if (debug_flag) {
        fprintf(stderr, "%s DEBUG: running unshare() with flags: ", prog_name);
        if (unshare_flags & CLONE_FS)
            fprintf(stderr, "CLONE_FS ");
        if (unshare_flags & CLONE_NEWCGROUP)
            fprintf(stderr, "CLONE_NEWCGROUP ");
        if (unshare_flags & CLONE_NEWIPC)
            fprintf(stderr, "CLONE_NEWIPC ");
        if (unshare_flags & CLONE_NEWNET)
            fprintf(stderr, "CLONE_NEWNET ");
        if (unshare_flags & CLONE_NEWNS)
            fprintf(stderr, "CLONE_NEWNS ");
        if (unshare_flags & CLONE_NEWUSER)
            fprintf(stderr, "CLONE_NEWUSER ");
        if (unshare_flags & CLONE_NEWUTS)
            fprintf(stderr, "CLONE_NEWUTS ");
        if (unshare_flags & CLONE_SYSVSEM)
            fprintf(stderr, "CLONE_SYSVSEM ");
        fprintf(stderr, "\n");
    }

    // TODO: add commandline parameters to configure which namespace to
    // unshare()
    // TODO: also unshare(): CLONE_NEWNET, CLONE_NEWPID (requires forking to
    // work properly)
    // TODO: maybe also unshare(): CLONE_NEWUSER, CLONE_NEWUTS, CLONE_SYSVSEM
    // TODO: should we use clone() instead of unshare in case of CLONE_NEWPID?
    // TODO: check whether the namespaces are destroyed when the (last)
    //       process exists, ...  or if they are left dangling.
    if (unshare(unshare_flags) == -1)
        err(1, "unshare(), flags = %i", unshare_flags);

    bind_mount(path_chroot, path_chroot, BIND_MOUNT_FREE_NONE);

    if (mount("none", path_chroot, NULL, MS_PRIVATE, NULL) == -1)
        err(1, "mount() make private %s", path_chroot);

    buf = malloc(buf_sz = INITIAL_BUF_SZ);
    if (buf == NULL)
        err(1, "malloc()");

    if (concatenate_paths_into_buf(&buf, &buf_sz, path_chroot,
                                   path_mountpoint) == -1) {
        free(buf);
        err(1, "concatenate_paths_into_buf()");
    }

    bind_mount(path_data, buf, BIND_MOUNT_FREE_TARGET);

    for (i = 0; argv_others[i] != NULL && *argv_others[i] == '='; i++) {
        if (concatenate_paths_into_buf(&buf, &buf_sz, path_chroot,
                                       argv_others[i] + 1) == -1) {
            free(buf);
            err(1, "concatenate_paths_into_buf()");
        }

        bind_mount(argv_others[i] + 1, buf, BIND_MOUNT_FREE_TARGET);
    }

    free(buf);

    if (chroot(path_chroot) == -1)
        err(1, "chroot() to %s", path_chroot);

    if (chdir(path_mountpoint) == -1)
        err(1, "chdir() to %s", path_mountpoint);

    execve_envp[0] = NULL;

    if (execve(path_prog, argv_execve, execve_envp) == -1)
        err(1, "execve() in chroot %s of %s", path_prog, path_chroot);

    return 0;
}
