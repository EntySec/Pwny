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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <log.h>
#include <net_client.h>
#include <ev.h>

#include <io.h>
#include <link.h>
#include <queue.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

io_t *io_create(void)
{
    io_t *io;

    io = calloc(1, sizeof(*io));

    if (io == NULL)
    {
        return NULL;
    }

    if ((io->ingress = queue_create()) == NULL)
    {
        goto fail;
    }

    if ((io->egress = queue_create()) == NULL)
    {
        goto fail;
    }

    return io;

fail:
    io_free(io);
    return NULL;
}

void io_add_pipes(io_t *io, int in_pipe, int out_pipe)
{
    io->pipe[0] = in_pipe;
    io->pipe[1] = out_pipe;
}

void io_start(io_t *io)
{
    ev_io_init(&io->io, io_read, io->pipe[0], EV_READ);
    io->io.data = io;
    ev_io_start(io->loop, &io->io);
}

void io_setup(io_t *io, struct ev_loop *loop)
{
    io->loop = loop;
}

void io_set_links(io_t *io,
                  link_t read_link,
                  link_t write_link,
                  link_event_t event_link,
                  void *data)
{
    io->read_link = read_link;
    io->write_link = write_link;
    io->event_link = event_link;
    io->link_data = data != NULL ? data : io;
}

void io_read(struct ev_loop *loop, struct ev_io *w, int events)
{
    io_t *io;

    io = w->data;

    if (io->read_link)
    {
        io->read_link(io->link_data);
    }
}

void io_write(io_t *io)
{
    if (io->write_link)
    {
        io->write_link(io->link_data);
    }
}

void io_stop(io_t *io)
{
    ev_io_stop(io->loop, &io->io);

    close(io->pipe[0]);
    close(io->pipe[1]);
}

void io_free(io_t *io)
{
    if (io != NULL)
    {
        queue_free(io->ingress);
        queue_free(io->egress);

        free(io);
    }
}
