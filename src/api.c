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
#include <string.h>
#include <stdlib.h>
#include <string.h>

#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <log.h>
#include <calls.h>

#include <tlv_types.h>

#include <uthash/uthash.h>

tlv_pkt_t *api_craft_tlv_pkt(int status)
{
    tlv_pkt_t *c2_pkt = tlv_pkt_create();
    tlv_pkt_add_int(c2_pkt, TLV_TYPE_STATUS, status);

    return c2_pkt;
}

void api_calls_register(api_calls_t **api_calls)
{
    register_api_calls(api_calls);
}

void api_call_register(api_calls_t **api_calls, int tag, api_t handler)
{
    api_calls_t *api_call;
    HASH_FIND_INT(*api_calls, &tag, api_call);

    if (api_call == NULL)
    {
        api_calls_t *api_call_new = calloc(1, sizeof(*api_call_new));

        if (api_call_new != NULL)
        {
            api_call_new->tag = tag;
            api_call_new->handler = handler;

            HASH_ADD_INT(*api_calls, tag, api_call_new);
            log_debug("* Registered C2 API call tag (%d)\n", tag);
        }
    }
}

tlv_pkt_t *api_call_make(api_calls_t **api_calls, c2_t *c2, int tag)
{
    api_calls_t *api_call;

    log_debug("* Looking for C2 API call tag (%d)\n", tag);
    HASH_FIND_INT(*api_calls, &tag, api_call);

    if (api_call == NULL)
    {
        log_debug("* C2 API call tag was not found (%d)\n", tag);
        return NULL;
    }

    return api_call->handler(c2);
}

void api_calls_free(api_calls_t *api_calls)
{
    api_calls_t *api_call;

    for (api_call = api_calls; api_call != NULL; api_call = api_call->hh.next)
    {
        log_debug("* Freed C2 API call tag (%d)\n", api_call->tag);

        HASH_DEL(api_calls, api_call);
        free(api_call);
    }

    free(api_calls);
}
