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

#ifndef _NET_SERVER_H_
#define _NET_SERVER_H_

#include <ev.h>
#include <link.h>

#include <net_client.h>

enum NET_SERVER_STATUS
{
    NET_SERVER_CLIENT,
};

typedef struct
{
    struct ev_loop *loop;
    struct ev_io event_io;

    enum NET_PROTO proto;

    int listener;
    void *link_data;

    link_t read_link;
    link_t write_link;
    link_event_t event_link;
} net_server_t;

net_server_t *net_server_create(void);

int net_server_start(net_server_t *net_server, enum NET_PROTO proto,
                     char *host, int port);

void net_server_setup(net_server_t *net_server, struct ev_loop *loop);
void net_server_set_links(net_server_t *net_server,
                          link_t read_link,
                          link_t write_link,
                          link_event_t event_link,
                          void *data);

void net_server_stop(net_server_t *net_server);
void net_server_free(net_server_t *net_server);

#endif
