/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#if IS_LINUX
#include <syscall.h>
#endif

/*
#ifndef IS_IPHONE
#include <injector.h>
#include <injector_internal.h>
#endif*/

#include <c2.h>
#include <log.h>
#include <migrate.h>

#ifndef IS_WINDOWS
#include <dlfcn.h>
#endif

ssize_t shared_read_sock(int shared, void *buf,
                         size_t length, int *sock)
{
    ssize_t bytes_read;

    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *pcmsghdr;

    char buffer[CMSG_SPACE(sizeof(int))];

    iov.iov_base = buf;
    iov.iov_len = length;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buffer;
    msg.msg_controllen = sizeof(buffer);
    msg.msg_flags = 0;

    bytes_read = recvmsg(shared, &msg, 0);
    if (bytes_read < 0)
    {
        return -1;
    }

    pcmsghdr = CMSG_FIRSTHDR(&msg);
    *sock = *((int*)CMSG_DATA(pcmsghdr));

    return bytes_read;
}

ssize_t shared_send_sock(int shared, const void *buf,
                         size_t length, int sock)
{
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *pcmsghdr;

    char buffer[CMSG_SPACE(sizeof(int))];

    iov.iov_base = (void*)buf;
    iov.iov_len = length;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buffer;
    msg.msg_controllen = sizeof(buffer);
    msg.msg_flags = 0;

    pcmsghdr = CMSG_FIRSTHDR(&msg);
    pcmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
    pcmsghdr->cmsg_level = SOL_SOCKET;
    pcmsghdr->cmsg_type = SCM_RIGHTS;

    *((int*)CMSG_DATA(pcmsghdr)) = sock;
    return sendmsg(shared, &msg, 0);
}

int migrate_init(pid_t pid, int length, unsigned char *buffer)
{/*
#if IS_LINUX
    int memfd;
    char image[PATH_MAX];

    memfd = syscall(SYS_memfd_create, "", MFD_CLOEXEC);

    if (fd >= 0)
    {
        write(memfd, buffer, length);
        sprintf(image, "/proc/self/fd/%d", memfd);

        migrate_inject(pid, image);
        return 0;
    }
#endif*/

    return -1;
}

int migrate_inject(pid_t pid, char *image)
{/*
#ifndef IS_IPHONE
#ifndef IS_WINDOWS
    long retval;
    size_t func_addr;
#endif

    injector_t *injector;
    void *handle;

    if (injector_attach(&injector, pid) < 0)
    {
        return -1;
    }

    log_debug("* Attached to the process (%d)\n", pid);

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (injector_inject_in_cloned_thread(injector, image, handle) < 0)
    {
        goto fail;
    }
#else
    if (injector_inject(injector, image, handle) < 0)
    {
        goto fail;
    }
#endif

    log_debug("* Injected to the process (%d)\n", pid);
    injector_detach(injector);

    return 0;

fail:
    log_debug("* Failed to do inject (%s)\n", injector_error());
    injector_detach(injector);

#endif*/
    return -1;
}
