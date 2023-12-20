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

#ifndef _FS_H_
#define _FS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>
#include <pipe.h>

#define FS_BASE 4

#define FS_PIPE_FILE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        FS_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_MODE TLV_TYPE_CUSTOM(TLV_TYPE_STRING, FS_BASE, API_TYPE)

int fs_create(pipe_t *pipe, c2_t *c2)
{
    char path[128];
    char mode[128];

    FILE *file;

    tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, path);
    tlv_pkt_get_string(c2->request, TLV_TYPE_MODE, mode);

    file = fopen(path, mode);

    if (!file)
    {
        return -1;
    }

    pipe->data = file;
    return 0;
}

int fs_read(pipe_t *pipe, void *buffer, int length)
{
    FILE *file;

    file = pipe->data;
    return fread(buffer, 1, length, file);
}

int fs_write(pipe_t *pipe, void *buffer, int length)
{
    FILE *file;

    file = pipe->data;
    return fwrite(buffer, 1, length, file);
}

int fs_seek(pipe_t *pipe, int offset, int whence)
{
    FILE *file;

    file = pipe->data;
    return fseek(file, offset, whence);
}

int fs_tell(pipe_t *pipe)
{
    FILE *file;

    file = pipe->data;
    return ftell(file);
}

int fs_destroy(pipe_t *pipe, c2_t *c2)
{
    FILE *file;

    file = pipe->data;
    return fclose(file);
}

void register_fs_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    callbacks.create_cb = fs_create;
    callbacks.read_cb = fs_read;
    callbacks.write_cb = fs_write;
    callbacks.seek_cb = fs_seek;
    callbacks.tell_cb = fs_tell;
    callbacks.destroy_cb = fs_destroy;

    pipe_register(pipes, FS_PIPE_FILE, callbacks);
}

#endif
