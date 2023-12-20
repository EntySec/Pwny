/*
 * MIT License
 *
 * Copyright (c) 2020-2023 EntySec
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

#include <ev.h>
#include <netdb.h>

#include <sys/types.h>

#include <link.h>
#include <queue.h>

#define NET_QUEUE_SIZE 65535

enum NET_PROTO
{
    NET_PROTO_FILE,
    NET_PROTO_TCP,
};

typedef struct
{
    struct ev_io io;
    struct ev_loop *loop;

    int proto;
    int sock;

    queue_t *ingress;
    queue_t *egress;

    void *link_data;
    link_t read_link;
    link_t write_link;
} net_t;

int net_block_sock(int sock);

net_t *net_create(int sock, int proto);

void net_setup(net_t *net, struct ev_loop *loop);
void net_start(net_t *net);

void net_set_links(net_t *net,
                   link_t read_link,
                   link_t write_link,
                   void *data);

void net_read_tcp(net_t *net);
void net_write_tcp(net_t *net);

void net_read_file(net_t *net);
void net_write_file(net_t *net);

void net_read(struct ev_loop *loop, struct ev_io *w, int events);
void net_write(net_t *net);

void net_free(net_t *net);

#endif