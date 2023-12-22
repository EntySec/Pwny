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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <ev.h>

#include <queue.h>
#include <child.h>

#include <uthash/uthash.h>

#ifndef IS_IPHONE
#include <pawn.h>
#endif

void child_set_links(child_t *child,
                     link_t out_link,
                     link_t err_link,
                     link_t exit_link,
                     void *data)
{
    child->out_link = out_link;
    child->err_link = err_link;
    child->exit_link = exit_link;
    child->link_data = data != NULL ? data : child;
}

size_t child_read(child_t *child, void *buffer, size_t length)
{
    size_t bytes;

    if ((bytes = queue_remove(child->out_queue.queue, buffer, length)) < length)
    {
        bytes += queue_remove(child->err_queue.queue, buffer + bytes, length - bytes);
    }

    return bytes;
}

size_t child_write(child_t *child, void *buffer, size_t length)
{
    ssize_t count;
    ssize_t stat;

    for (count = 0; count < length; NULL)
    {
        do
        {
            stat = write(child->in, buffer + count, length - count);
        }
        while (stat == -1 && errno == EINTR);

        if (stat < 0)
        {
            break;
        }

        count += stat;
    }

    return count > 0 ? count : -1;
}

void child_out(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;

    child = w->data;

    if (queue_from_fd(child->out_queue.queue, w->fd) > 0)
    {
        if (child->out_link)
        {
            child->out_link(child->link_data);
        }
    }
}

void child_err(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;

    child = w->data;

    if (queue_from_fd(child->err_queue.queue, w->fd) > 0)
    {
        if (child->err_link)
        {
            child->err_link(child->link_data);
        }
    }
}

void child_exit(struct ev_loop *loop, struct ev_child *w, int revents)
{
    child_t *child;

    child = w->data;

    ev_child_stop(loop, w);

    if (child->exit_link)
    {
        child->exit_link(child->link_data);
    }

    child_destroy(child);
}

void child_from_image(child_t *child, unsigned char *image)
{
    char *argv[1];

    ev_loop_fork(EV_DEFAULT);
    ev_loop_destroy(EV_DEFAULT_UC);

    argv[0] = "pwny";

#if IS_MACOS
    pawn_exec_bundle(image, argv, NULL);
#elif IS_LINUX
    pawn_exec_fd(image, argv, NULL);
#elif IS_WINDOWS
    pawn_exec(image, argv);
#endif

    abort();
}

void child_from_file(child_t *child, char *filename)
{
    ev_loop_fork(EV_DEFAULT);
    ev_loop_destroy(EV_DEFAULT_UC);

    abort();
}

child_t *child_create(char *filename, unsigned char *image)
{
    child_t *child;
    int in_pair[2];
    int out_pair[2];
    int err_pair[2];

    if (pipe(err_pair) == -1)
    {
        return NULL;
    }

    child = calloc(1, sizeof(*child));

    if (child == NULL)
    {
        return NULL;
    }

    if (pipe(in_pair) == -1)
    {
        return NULL;
    }

    if (pipe(out_pair) == -1)
    {
        return NULL;
    }

    child->pid = fork();

    if (child->pid == 0)
    {
        dup2(in_pair[0], STDIN_FILENO);
        dup2(out_pair[1], STDOUT_FILENO);
        dup2(err_pair[1], STDERR_FILENO);

        close(err_pair[1]);
        close(err_pair[0]);

        if (image != NULL)
        {
            child_from_image(child, image);
        }
        else if (filename != NULL)
        {
            child_from_file(child, filename);
        }

        return NULL;
    }
    else if (child->pid == -1)
    {
        close(in_pair[1]);
        close(in_pair[0]);
        close(out_pair[1]);
        close(out_pair[0]);
        close(err_pair[1]);
        close(err_pair[0]);
        free(child);

        return NULL;
    }

    child->child.data = child;

    ev_child_init(&child->child, child_exit, child->pid, 0);
    ev_child_start(child->loop, &child->child);

    fcntl(in_pair[1], F_SETFL, O_NONBLOCK);
    child->in = in_pair[1];

    fcntl(out_pair[0], F_SETFL, O_NONBLOCK);

    child->out = out_pair[0];
    child->out_queue.io.data = child;
    child->out_queue.queue = queue_create();

    ev_io_init(&child->out_queue.io, child_out, child->out, EV_READ);
    ev_io_start(child->loop, &child->out_queue.io);

    fcntl(err_pair[0], F_SETFL, O_NONBLOCK);

    child->err = err_pair[0];
    child->err_queue.io.data = child;
    child->err_queue.queue = queue_create();

    ev_io_init(&child->err_queue.io, child_err, child->err, EV_READ);
    ev_io_start(child->loop, &child->err_queue.io);

    close(in_pair[0]);
    close(out_pair[1]);
    close(err_pair[1]);

    return child;
}

int child_kill(child_t *child)
{
    return kill(child->pid, SIGINT);
}

void child_destroy(child_t *child)
{
    close(child->in);
    close(child->out);
    close(child->err);

    ev_io_stop(child->loop, &child->out_queue.io);
    ev_io_stop(child->loop, &child->err_queue.io);

    queue_free(child->out_queue.queue);
    queue_free(child->err_queue.queue);
}
