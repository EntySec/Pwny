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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <queue.h>
#include <log.h>

#include <uthash/utlist.h>

static void queue_data_free(queue_data_t *data)
{
    if (data->buffer)
    {
        free(data->buffer);
        free(data);
    }
}

queue_t *queue_create(void)
{
    return calloc(1, sizeof(queue_t));
}

void queue_drain_all(queue_t *queue)
{
    queue_data_t *buffer;
    queue_data_t *temp;

    LL_FOREACH_SAFE(queue->data, buffer, temp)
    {
        LL_DELETE(queue->data, buffer);
        queue_data_free(buffer);
    }

    queue->bytes = 0;
}

int queue_add_raw(queue_t *queue, const void *data, size_t length)
{
    queue_data_t *buffer;

    buffer = calloc(1, sizeof(*buffer));
    if (buffer == NULL)
    {
        return -1;
    }

    buffer->buffer = malloc(length);
    if (buffer->buffer == NULL)
    {
        queue_data_free(buffer);
        return -1;
    }

    memcpy(buffer->buffer, data, length);
    buffer->offset = 0;
    buffer->length = length;

    LL_APPEND(queue->data, buffer);
    queue->bytes += length;

    log_debug("* Added to queue (%d)\n", length);

    return 0;
}

int queue_add_str(queue_t *queue, char *str)
{
    return queue_add_raw(queue, str, strlen(str));
}

void *queue_peek(queue_t *queue, size_t *length)
{
    void *data;

    data = NULL;

    if (queue->data)
    {
        data = queue->data->buffer;
        *length = queue->data->length;
    }

    return data;
}

void *queue_pop(queue_t *queue, size_t *length)
{
    void *data;

    data = NULL;

    if (queue->data)
    {
        queue_data_t *buffer = queue->data;
        LL_DELETE(queue->data, buffer);

        data = buffer->buffer;
        *length = buffer->length;

        queue->bytes -= buffer->length;
        free(buffer);
    }

    return data;
}

size_t queue_copy(queue_t *queue, void *data, size_t length)
{
    size_t copied;
    size_t bytes;

    queue_data_t *buffer;

    copied = 0;

    LL_FOREACH(queue->data, buffer)
    {
        bytes = TYPESAFE_MIN(length, buffer->length - buffer->offset);
        memcpy(data, buffer->buffer + buffer->offset, bytes);

        data += bytes;
        length -= bytes;
        copied += bytes;

        if (length <= 0)
        {
            break;
        }
    }

    return copied;
}

size_t queue_drain(queue_t *queue, size_t length)
{
    size_t drained;
    size_t bytes;

    queue_data_t *buffer;
    queue_data_t *temp;

    drained = 0;

    LL_FOREACH_SAFE(queue->data, buffer, temp)
    {
        bytes = TYPESAFE_MIN(length, buffer->length - buffer->offset);
        length -= bytes;
        buffer->offset += bytes;

        if (buffer->offset == buffer->length)
        {
            LL_DELETE(queue->data, buffer);
            queue_data_free(buffer);
        }

        drained += bytes;
        if (length <= 0)
        {
            break;
        }
    }

    queue->bytes -= drained;
    return drained;
}

size_t queue_remove(queue_t *queue, void *data, size_t length)
{
    size_t removed;
    size_t bytes;

    queue_data_t *buffer;
    queue_data_t *temp;

    removed = 0;

    LL_FOREACH_SAFE(queue->data, buffer, temp)
    {
        bytes = TYPESAFE_MIN(length, buffer->length - buffer->offset);
        memcpy(data, buffer->buffer + buffer->offset, bytes);

        data += bytes;
        length -= bytes;
        buffer->offset += bytes;

        if (buffer->offset == buffer->length)
        {
            LL_DELETE(queue->data, buffer);
            queue_data_free(buffer);
        }

        removed += bytes;
        if (length <= 0)
        {
            break;
        }
    }

    queue->bytes -= removed;
    return removed;
}

ssize_t queue_remove_all(queue_t *queue, void **data)
{
    void *buffer;
    size_t bytes;

    buffer = malloc(queue->bytes);
    if (buffer == NULL)
    {
        return -1;
    }

    bytes = queue_remove(queue, buffer, queue->bytes);
    *data = buffer;

    return bytes;
}

ssize_t queue_move_all(queue_t *queue, queue_t *new_queue)
{
    size_t moved;

    queue_data_t *buffer;
    queue_data_t *temp;

    moved = 0;

    LL_FOREACH_SAFE(queue->data, buffer, temp)
    {
        LL_DELETE(queue->data, buffer);
        queue->bytes -= buffer->length;
        LL_APPEND(new_queue->data, buffer);
        new_queue->bytes += buffer->length;
        moved += buffer->length;
    }

    return moved;
}

size_t queue_from_fd(queue_t *queue, int fd)
{
    char buffer[QUEUE_FD_MAX];
    ssize_t count;
    size_t length;

    length = 0;

    while ((count = read(fd, buffer, sizeof(buffer))) > 0)
    {
        queue_add_raw(queue, buffer, count);
        length += count;
    }

    return length;
}

void queue_free(queue_t *queue)
{
    if (queue)
    {
        free(queue);
    }
}
