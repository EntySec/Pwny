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

#ifndef _NET_CLIENT_H_
#define _NET_CLIENT_H_

#include <ev.h>
#include <io.h>
#include <link.h>
#include <queue.h>

#define NET_QUEUE_SIZE 8192

enum NET_STATUS
{
    NET_STATUS_CLOSED,
    NET_STATUS_RESOLVE,
    NET_STATUS_CONNECTING,
    NET_STATUS_OPEN
};

enum NET_PROTO
{
    NET_PROTO_TCP,
    NET_PROTO_UDP,
    NET_PROTO_FILE,
    NET_PROTO_UNIX,
};

typedef struct
{
    struct ev_loop *loop;
    struct ev_timer timer;
    struct ev_io event_io;
    float delay;

    io_t *io;
    char *uri;
    char *host;
    char *port;

    struct addrinfo *dest;
    struct addrinfo *src;

    char *src_addr;
    uint16_t src_port;

    enum NET_PROTO proto;
    enum NET_STATUS status;

    void *link_data;
    int sent;

    link_t read_link;
    link_t write_link;
    link_event_t event_link;
} net_t;

net_t *net_create(void);

void net_add_pipes(net_t *net, int in_pipe, int out_pipe);
int net_add_sock(net_t *net, int sock, int proto);
int net_add_uri(net_t *net, char *uri);

void net_set_src(net_t *net, char *addr, uint16_t port);

void net_setup(net_t *net, struct ev_loop *loop);
void net_start(net_t *net);

int net_nonblock_sock(int sock);
void net_set_delay(net_t *net, float delay);
void net_timer(struct ev_loop *loop, struct ev_timer *w, int revents);
void net_set_links(net_t *net,
                   link_t read_link,
                   link_t write_link,
                   link_event_t event_link,
                   void *data);

void net_stop_timer(net_t *net);

void net_stop(net_t *net);
void net_free(net_t *net);

#endif