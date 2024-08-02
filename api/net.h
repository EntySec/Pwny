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

#ifndef _NET_H_
#define _NET_H_

#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <core.h>
#include <pipe.h>
#include <tlv_types.h>

#define NET_BASE 4

#define NET_TUNNELS \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL)
#define NET_ADD_TUNNEL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL + 1)
#define NET_SUSPEND_TUNNEL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL + 2)
#define NET_ACTIVATE_TUNNEL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL + 3)
#define NET_RESTART_TUNNEL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL + 4)

#define NET_CLIENT_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        NET_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_TUNNEL_URI    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NET_BASE, API_TYPE)

#define TLV_TYPE_TUNNEL_ALGO       TLV_TYPE_CUSTOM(TLV_TYPE_INT, NET_BASE, API_TYPE)
#define TLV_TYPE_TUNNEL_ID         TLV_TYPE_CUSTOM(TLV_TYPE_INT, NET_BASE, API_TYPE + 1)
#define TLV_TYPE_TUNNEL_DELAY      TLV_TYPE_CUSTOM(TLV_TYPE_INT, NET_BASE, API_TYPE + 2)
#define TLV_TYPE_TUNNEL_KEEP_ALIVE TLV_TYPE_CUSTOM(TLV_TYPE_INT, NET_BASE, API_TYPE + 3)

static tlv_pkt_t *net_tunnels(c2_t *c2)
{
    c2_t *curr_c2;
    c2_t *c2_tmp;
    core_t *core;
    tlv_pkt_t *result;
    tlv_pkt_t *tunnel;

    core = c2->data;
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    HASH_ITER(hh, core->c2, curr_c2, c2_tmp)
    {
        tunnel = tlv_pkt_create();

        tlv_pkt_add_u32(tunnel, TLV_TYPE_TUNNEL_ID, curr_c2->id);
        tlv_pkt_add_u32(tunnel, TLV_TYPE_TUNNEL_ALGO, curr_c2->crypt->algo);
        tlv_pkt_add_string(tunnel, TLV_TYPE_TUNNEL_URI, curr_c2->tunnel->uri);

        if (curr_c2->id == c2->id)
        {
            tlv_pkt_add_u32(tunnel, TLV_TYPE_BOOL, 1);
        }
        else
        {
            tlv_pkt_add_u32(tunnel, TLV_TYPE_BOOL, 0);
        }

        tlv_pkt_add_u32(tunnel, TLV_TYPE_INT, curr_c2->tunnel->active);
        tlv_pkt_add_u32(tunnel, TLV_TYPE_TUNNEL_KEEP_ALIVE, curr_c2->tunnel->keep_alive);
        tlv_pkt_add_u32(tunnel, TLV_TYPE_TUNNEL_DELAY, (int)curr_c2->tunnel->delay);

        tlv_pkt_add_tlv(result, TLV_TYPE_GROUP, tunnel);
        tlv_pkt_destroy(tunnel);
    }

    return result;
}

tlv_pkt_t *net_add_tunnel(c2_t *c2)
{
    core_t *core;
    char uri[256];

    core = c2->data;
    tlv_pkt_get_string(c2->request, TLV_TYPE_TUNNEL_URI, uri);

    if (core_add_uri(core, uri) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

tlv_pkt_t *net_suspend_tunnel(c2_t *c2)
{
    core_t *core;
    c2_t *curr_c2;
    c2_t *c2_tmp;
    int id;

    core = c2->data;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_ID, &id);

    if (id == c2->id)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    HASH_ITER(hh, core->c2, curr_c2, c2_tmp)
    {
        if (curr_c2->id != id || !curr_c2->tunnel->active)
        {
            continue;
        }

        c2_stop(curr_c2);
        break;
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

tlv_pkt_t *net_activate_tunnel(c2_t *c2)
{
    core_t *core;
    c2_t *curr_c2;
    c2_t *c2_tmp;
    int id;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_ID, &id);

    HASH_ITER(hh, core->c2, curr_c2, c2_tmp)
    {
        if (curr_c2->id != id || curr_c2->tunnel->active)
        {
            continue;
        }

        c2_start(curr_c2);
        break;
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

tlv_pkt_t *net_restart_tunnel(c2_t *c2)
{
    core_t *core;
    c2_t *curr_c2;
    c2_t *c2_tmp;

    int id;
    int delay;
    int keep_alive;

    core = c2->data;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_DELAY, &delay);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_KEEP_ALIVE, &keep_alive);

    HASH_ITER(hh, core->c2, curr_c2, c2_tmp)
    {
        if (curr_c2->id != id)
        {
            continue;
        }

        curr_c2->tunnel->delay = (float)delay;
        curr_c2->tunnel->keep_alive = keep_alive;

        tunnel_start(curr_c2->tunnel);
        break;
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

void net_client_event_link(int event, void *data)
{
    pipe_t *pipe;
    tlv_pkt_t *result;

    pipe = data;
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, NET_CLIENT_PIPE);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, pipe->id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_HEARTBEAT, event);

    c2_enqueue_tlv(pipe->c2, result);
    tlv_pkt_destroy(result);
}

void net_client_read_link(void *data)
{
    pipe_t *pipe;
    size_t length;
    tunnel_t *tunnel;
    tlv_pkt_t *result;
    unsigned char *buffer;

    pipe = data;
    tunnel = pipe->data;
    length = tunnel->ingress->bytes;

    buffer = malloc(length);
    if (buffer == NULL)
    {
        return;
    }

    queue_remove(tunnel->ingress, buffer, length);
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, NET_CLIENT_PIPE);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, pipe->id);
    tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER, buffer, length);

    c2_enqueue_tlv(pipe->c2, result);

    tlv_pkt_destroy(result);
    free(buffer);
}

static int net_client_create(pipe_t *pipe, c2_t *c2)
{
    char uri[256];
    tunnels_t *tunnel;
    tunnel_t *ctx;
    core_t *core;

    core = c2->data;
    tlv_pkt_get_string(c2->request, TLV_TYPE_TUNNEL_URI, uri);

    tunnel = tunnel_find(core->tunnels, uri);
    if (tunnel == NULL)
    {
        log_debug("* Failed to find protocol for (%s)\n", uri);
        return -1;
    }

    ctx = tunnel_create(tunnel);
    if (ctx == NULL)
    {
        log_debug("* Failed to create tunnel for C2 (%d)\n", c2->id);
        return -1;;
    }

    tunnel_set_uri(ctx, uri);
    tunnel_setup(ctx, c2->loop);

    if (pipe->flags & PIPE_INTERACTIVE)
    {
        tunnel_set_links(ctx, net_client_read_link, NULL,
                         net_client_event_link, pipe);
    }
    else
    {
        tunnel_set_links(ctx, NULL, NULL, NULL, pipe);
    }

    if (tunnel_init(ctx) < 0)
    {
        log_debug("* Failed to initialize tunnel for C2 (%d)\n", c2->id);
        return -1;
    }

    tunnel_start(ctx);
    pipe->data = ctx;
    pipe->c2 = c2;
    return 0;
}

static int net_client_tell(pipe_t *pipe)
{
    tunnel_t *tunnel;

    tunnel = pipe->data;
    return tunnel->ingress->bytes;
}

static int net_client_read(pipe_t *pipe, void *buffer, int length)
{
    tunnel_t *tunnel;

    tunnel = pipe->data;
    return queue_remove(tunnel->ingress, buffer, length);
}

static int net_client_write(pipe_t *pipe, void *buffer, int length)
{
    tunnel_t *tunnel;

    tunnel = pipe->data;
    queue_add_raw(tunnel->egress, buffer, length);
    tunnel_write(tunnel, tunnel->egress);

    return 0;
}

static int net_client_destroy(pipe_t *pipe, c2_t *c2)
{
    tunnel_t *tunnel;

    tunnel = pipe->data;
    tunnel_exit(tunnel);
    tunnel_free(tunnel);

    return 0;
}

void register_net_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, NET_TUNNELS, net_tunnels);
    api_call_register(api_calls, NET_ADD_TUNNEL, net_add_tunnel);
    api_call_register(api_calls, NET_SUSPEND_TUNNEL, net_suspend_tunnel);
    api_call_register(api_calls, NET_ACTIVATE_TUNNEL, net_activate_tunnel);
    api_call_register(api_calls, NET_RESTART_TUNNEL, net_restart_tunnel);
}

void register_net_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t client_callbacks;

    client_callbacks.create_cb = net_client_create;
    client_callbacks.read_cb = net_client_read;
    client_callbacks.write_cb = net_client_write;
    client_callbacks.tell_cb = net_client_tell;
    client_callbacks.destroy_cb = net_client_destroy;

    api_pipe_register(pipes, NET_CLIENT_PIPE, client_callbacks);
}

#endif