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

#ifndef _QUEUE_H_
#define _QUEUE_H_

#include <stdlib.h>

#define QUEUE_FD_MAX 8192

#define TYPESAFE_MAX(a, b) ({ \
        typeof(a) _a = (a);   \
		typeof(b) _b = (b);   \
		(void) (&_a == &_b);  \
		_a > _b ? _a : _b; })

#define TYPESAFE_MIN(a, b) ({ \
        typeof(a) _a = (a);   \
		typeof(b) _b = (b);   \
		(void) (&_a == &_b);  \
		_a < _b ? _a : _b; })

typedef struct queue_data
{
    size_t offset;
    size_t length;
    struct queue_data *next;
    char *buffer;
} queue_data_t;

typedef struct
{
    queue_data_t *data;
    size_t bytes;
} queue_t;

queue_t *queue_create(void);

void queue_drain_all(queue_t *queue);

int queue_add_raw(queue_t *queue, const void *data, size_t length);
int queue_add_str(queue_t *queue, char *str);

void *queue_peek(queue_t *queue, size_t *length);
void *queue_pop(queue_t *queue, size_t *length);

size_t queue_copy(queue_t *queue, void *data, size_t length);
size_t queue_drain(queue_t *queue, size_t length);
size_t queue_remove(queue_t *queue, void *data, size_t length);

ssize_t queue_remove_all(queue_t *queue, void **data);
ssize_t queue_move_all(queue_t *queue, queue_t *new_queue);

size_t queue_from_fd(queue_t *queue, int fd);

void queue_free(queue_t *queue);

#endif