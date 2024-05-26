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

#ifndef _API_H_
#define _API_H_

#include <sigar.h>

#include <c2.h>
#include <tlv.h>
#include <tabs.h>

#include <uthash/uthash.h>

#define API_CALL 1
#define API_TYPE 1

#define API_CALL_INTERNAL 10000
#define API_CALL_STATIC   20000
#define API_CALL_DYNAMIC  40000

typedef tlv_pkt_t *(*api_t)(c2_t *);

typedef struct pipes_table pipes_t;
typedef struct pipe_callbacks pipe_callbacks_t;

typedef enum
{
    API_CALLBACK,
    API_SILENT,
    API_BREAK,
} api_signal_t;

typedef enum
{
    API_CALL_QUIT,
    API_CALL_SUCCESS,
    API_CALL_FAIL,
    API_CALL_WAIT,
    API_CALL_NOT_IMPLEMENTED,
    API_CALL_USAGE_ERROR,
    API_CALL_RW_ERROR,
} api_status_t;

typedef struct api_calls_table
{
    int tag;
    api_t handler;
    UT_hash_handle hh;
} api_calls_t;

api_signal_t api_process_c2(c2_t *c2, api_calls_t *api_calls, tabs_t *tabs);

tlv_pkt_t *api_craft_tlv_pkt(int status);
int api_call_make(api_calls_t **api_calls, c2_t *c2, int tag, tlv_pkt_t **result);

void api_call_register(api_calls_t **api_calls, int tag, api_t handler);
void api_pipe_register(pipes_t **pipes, int type, pipe_callbacks_t callbacks);

void api_calls_free(api_calls_t *api_calls);
void api_pipes_free(pipes_t *pipes);

#endif
