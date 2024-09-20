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

#include <uthash/uthash.h>

#include <tunnel.h>
#include <log.h>

void register_tunnel(tunnels_t **tunnels, char *proto,
                     tunnel_callbacks_t callbacks)
{
    tunnels_t *tunnel;
    tunnels_t *tunnel_new;

    HASH_FIND_STR(*tunnels, proto, tunnel);

    if (tunnel != NULL)
    {
        return;
    }

    tunnel_new = calloc(1, sizeof(*tunnel_new));

    if (tunnel_new != NULL)
    {
        tunnel_new->proto = strdup(proto);
        tunnel_new->callbacks = callbacks;

        HASH_ADD_STR(*tunnels, proto, tunnel_new);
        log_debug("* Registered tunnel (proto: %s)\n", proto);
    }
}

tunnels_t *tunnel_find(tunnels_t *tunnels, char *proto)
{
    tunnels_t *tunnel;
    tunnels_t *tunnel_tmp;

    HASH_ITER(hh, tunnels, tunnel, tunnel_tmp)
    {
        if (strncmp(proto, tunnel->proto, strlen(tunnel->proto)) == 0)
        {
            log_debug("* Found tunnel for protocol (%s)\n", proto);
            return tunnel;
        }
    }

    return NULL;
}

tunnel_t *tunnel_create(tunnels_t *tunnel)
{
    tunnel_t *new_tunnel;

    new_tunnel = calloc(1, sizeof(*new_tunnel));

    if (new_tunnel == NULL)
    {
        return NULL;
    }

    new_tunnel->callbacks = tunnel->callbacks;
    new_tunnel->keep_alive = 0;
    new_tunnel->active = 0;
    new_tunnel->delay = 1.0;

    return new_tunnel;
}

void tunnel_set_uri(tunnel_t *tunnel, char *uri)
{
    tunnel->uri = strdup(uri);
}

void tunnel_set_links(tunnel_t *tunnel,
                      link_t read_link,
                      link_t write_link,
                      link_event_t event_link,
                      void *data)
{
    tunnel->read_link = read_link;
    tunnel->write_link = write_link;
    tunnel->event_link = event_link;
    tunnel->link_data = data != NULL ? data : tunnel;
}

void tunnel_setup(tunnel_t *tunnel, struct ev_loop *loop)
{
    tunnel->loop = loop;
}

int tunnel_init(tunnel_t *tunnel)
{
    log_debug("* Initializing tunnel (%s)\n", tunnel->uri);

    if (tunnel->callbacks.init_cb)
    {
        return tunnel->callbacks.init_cb(tunnel);
    }

    return 0;
}

int tunnel_start(tunnel_t *tunnel)
{
    if (tunnel->callbacks.start_cb)
    {
        return tunnel->callbacks.start_cb(tunnel);
    }

    return 0;
}

void tunnel_write(tunnel_t *tunnel, queue_t *egress)
{
    if (tunnel->callbacks.write_cb)
    {
        return tunnel->callbacks.write_cb(tunnel, egress);
    }
}

void tunnel_exit(tunnel_t *tunnel)
{
    if (tunnel->callbacks.exit_cb)
    {
        return tunnel->callbacks.exit_cb(tunnel);
    }
}

void tunnel_free(tunnel_t *tunnel)
{
    free(tunnel->uri);
    free(tunnel);
}

void tunnels_free(tunnels_t *tunnels)
{
    tunnels_t *tunnel;
    tunnels_t *tunnel_tmp;

    HASH_ITER(hh, tunnels, tunnel, tunnel_tmp)
    {
        log_debug("* Freed tunnel (proto: %s)\n", tunnel->proto);
        free(tunnel->proto);

        HASH_DEL(tunnels, tunnel);
        free(tunnel);
    }

    free(tunnels);
}
