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

#ifndef _CHILD_H_
#define _CHILD_H_

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ev.h>

#include <link.h>
#include <queue.h>
#include <uthash/uthash.h>

#define CHILD_EV_FLAGS EVFLAG_NOENV | EVBACKEND_SELECT
#define CHILD_ALIVE 1
#define CHILD_DEAD 0

#define CHILD_FORCE_PTY   1 << 0
#define CHILD_NO_FORK     1 << 1

typedef struct
{
    int flags;
    char *args;
    char **argv;
    char **env;
} child_options_t;

typedef struct
{
    int in_pair[2];
    int out_pair[2];
    int err_pair[2];
} child_pipes_t;

typedef struct
{
    struct ev_io io;
    queue_t *queue;
} child_queue_t;

typedef struct
{
    pid_t pid;

    struct ev_loop *loop;
    struct ev_child child;

    child_queue_t out_queue;
    child_queue_t err_queue;

    int in;
    int out;
    int err;

    int status;
    void *link_data;

    link_t out_link;
    link_t err_link;
    link_t exit_link;

    UT_hash_handle hh;
} child_t;

void child_set_links(child_t *child,
                     link_t out_link,
                     link_t err_link,
                     link_t exit_link,
                     void *data);

child_t *child_create(char *filename, unsigned char *image, child_options_t *options);

void child_out(struct ev_loop *loop, struct ev_io *w, int events);
void child_err(struct ev_loop *loop, struct ev_io *w, int events);
void child_exit(struct ev_loop *loop, struct ev_child *w, int revents);

size_t child_read(child_t *child, void *buffer, size_t length);
size_t child_write(child_t *child, void *buffer, size_t length);

void child_kill(child_t *child);
void child_destroy(child_t *child);

#endif