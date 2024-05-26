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

#ifndef _IO_H_
#define _IO_H_

#include <ev.h>
#include <netdb.h>

#include <sys/types.h>

#include <link.h>
#include <queue.h>

typedef struct
{
    struct ev_io io;
    struct ev_loop *loop;

    int pipe[2];

    queue_t *ingress;
    queue_t *egress;

    void *link_data;
    link_t read_link;
    link_t write_link;
    link_event_t event_link;
} io_t;

io_t *io_create(void);
void io_add_pipes(io_t *io, int in_pipe, int out_pipe);

void io_setup(io_t *io, struct ev_loop *loop);
void io_start(io_t *io);

void io_set_links(io_t *io,
                  link_t read_link,
                  link_t write_link,
                  link_event_t event_link,
                  void *data);

void io_read(struct ev_loop *loop, struct ev_io *w, int events);
void io_write(io_t *io);

void io_stop(io_t *io);
void io_free(io_t *io);

#endif