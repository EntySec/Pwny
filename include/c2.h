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

#ifndef _C2_H_
#define _C2_H_

#include "tlv.h"

#include "uthash/uthash.h"

enum c2_api_call_statuses {
    API_CALL_SUCCESS, API_CALL_FAIL, API_CALL_WAIT,
    API_CALL_NOT_IMPLEMENTED, API_CALL_USAGE_ERROR,
    API_CALL_RW_ERROR, API_CALL_NOT_LOADED,
};

enum c2_api_call_builtins {
    API_QUIT, API_LOAD, API_UNLOAD, API_CALL,
};

enum c2_api_call_scopes {
    API_SCOPE_STDAPI,
};

typedef struct c2_api_call {
    int c2_api_call_scope;
    int c2_api_call_tag;
    int c2_api_call_status;
    char *c2_api_call_result;
} c2_api_call_t;

typedef c2_api_call_t *(*c2_api_t)(tlv_transport_pkt_t);

typedef struct c2_api_call_handlers {
    int c2_api_call_tag;
    c2_api_t c2_api_call_handler;
    UT_hash_handle hh;
} c2_api_call_handlers_t;

typedef struct c2_api_calls {
    int c2_api_call_scope;
    void *c2_api_call_plugin;
    c2_api_call_handlers_t *c2_api_call_handlers;
    UT_hash_handle hh;
} c2_api_calls_t;

tlv_transport_pkt_t craft_c2_tlv_pkt(tlv_transport_pkt_t, c2_api_call_t *);
c2_api_call_t *craft_c2_api_call_pkt(tlv_transport_pkt_t, int, char *);

c2_api_call_t *c2_make_api_call(c2_api_calls_t **, tlv_transport_pkt_t);
void c2_register_api_calls(c2_api_calls_t **);
void c2_register_api_call(c2_api_calls_t **, int, c2_api_t, int);

void c2_add_str(c2_api_call_t *, char *);

int c2_unload_api_calls(c2_api_calls_t **, int);
int c2_load_api_calls(c2_api_calls_t **, char *);

void c2_api_call_free(c2_api_call_t *);
void c2_api_calls_free(c2_api_calls_t *);

#endif /* _C2_H_ */
