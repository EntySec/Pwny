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

#ifndef _TUNNEL_H_
#define _TUNNEL_H_

#include <ev.h>
#include <link.h>
#include <queue.h>

#include <uthash/uthash.h>

typedef struct tunnels_table tunnels_t;
typedef struct tunnel_callbacks tunnel_callbacks_t;
typedef struct tunnel tunnel_t;

struct tunnel_callbacks
{
    int (*init_cb)(tunnel_t *tunnel);
    int (*start_cb)(tunnel_t *tunnel);
    void (*write_cb)(tunnel_t *tunnel, queue_t *egress);
    void (*exit_cb)(tunnel_t *tunnel);
};

struct tunnel
{
    char *uri;
    void *data;
    void *link_data;
    struct ev_loop *loop;

    float delay;
    int keep_alive;
    int active;

    queue_t *ingress;
    queue_t *egress;

    link_t read_link;
    link_t write_link;
    link_event_t event_link;

    tunnel_callbacks_t callbacks;
};

struct tunnels_table
{
    char *proto;
    tunnel_callbacks_t callbacks;
    UT_hash_handle hh;
};

void register_tunnel(tunnels_t **tunnels, char *proto,
                     tunnel_callbacks_t callbacks);

tunnels_t *tunnel_find(tunnels_t *tunnels, char *proto);
tunnel_t *tunnel_create(tunnels_t *tunnel);

void tunnel_set_links(tunnel_t *tunnel,
                      link_t read_link,
                      link_t write_link,
                      link_event_t event_link,
                      void *data);

void tunnel_set_uri(tunnel_t *tunnel, char *uri);

void tunnel_setup(tunnel_t *tunnel, struct ev_loop *loop);
int tunnel_init(tunnel_t *tunnel);
int tunnel_start(tunnel_t *tunnel);
void tunnel_exit(tunnel_t *tunnel);
void tunnel_write(tunnel_t *tunnel, queue_t *egress);

void tunnel_free(tunnel_t *tunnel);
void tunnels_free(tunnels_t *tunnels);

#endif