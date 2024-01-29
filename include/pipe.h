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

#ifndef _PIPE_H_
#define _PIPE_H_

#include <stdlib.h>

#include <c2.h>
#include <api.h>
#include <tlv.h>
#include <tlv_types.h>

#include <uthash/uthash.h>

#define PIPE_BASE 1

#define PIPE_READ \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL)
#define PIPE_WRITE \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL + 1)
#define PIPE_SEEK \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL + 2)
#define PIPE_TELL \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL + 3)
#define PIPE_CREATE \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL + 4)
#define PIPE_DESTROY \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL + 5)
#define PIPE_HEARTBEAT \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       PIPE_BASE, \
                       API_CALL + 6)

#define TLV_TYPE_PIPE_TYPE   TLV_TYPE_CUSTOM(TLV_TYPE_INT, PIPE_BASE, API_TYPE)
#define TLV_TYPE_PIPE_ID     TLV_TYPE_CUSTOM(TLV_TYPE_INT, PIPE_BASE, API_TYPE + 1)
#define TLV_TYPE_PIPE_LENGTH TLV_TYPE_CUSTOM(TLV_TYPE_INT, PIPE_BASE, API_TYPE + 2)
#define TLV_TYPE_PIPE_BUFFER TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, PIPE_BASE, API_TYPE)
#define TLV_TYPE_PIPE_OFFSET TLV_TYPE_CUSTOM(TLV_TYPE_INT, PIPE_BASE, API_TYPE + 3)
#define TLV_TYPE_PIPE_WHENCE TLV_TYPE_CUSTOM(TLV_TYPE_INT, PIPE_BASE, API_TYPE + 4)

#define PIPE_TYPE 1

#define PIPE_INTERNAL 10000
#define PIPE_STATIC   20000
#define PIPE_DYNAMIC  40000

typedef struct pipes_table pipes_t;
typedef struct pipe_callbacks pipe_callbacks_t;
typedef struct pipes pipe_t;

struct pipe_callbacks
{
    int (*create_cb)(pipe_t *pipe, c2_t *c2);
    int (*read_cb)(pipe_t *pipe, void *buffer, int length);
    int (*write_cb)(pipe_t *pipe, void *buffer, int length);
    int (*seek_cb)(pipe_t *pipe, int offset, int whence);
    int (*tell_cb)(pipe_t *pipe);
    int (*destroy_cb)(pipe_t *pipe, c2_t *c2);
    int (*heartbeat_cb)(pipe_t *pipe);
};

struct pipes
{
    int id;
    void *data;
    UT_hash_handle hh;
};

struct pipes_table
{
    int type;
    pipe_t *pipes;
    pipe_callbacks_t callbacks;
    UT_hash_handle hh;
};

void register_pipe_api_calls(api_calls_t **api_calls);

#endif