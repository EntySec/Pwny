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

#include <c2.h>
#include <tlv.h>
#include <log.h>
#include <calls.h>

#include <uthash/uthash.h>

/*
 * Create C2 TLV packet from existing TLV packet.
 */

tlv_pkt_t *create_c2_tlv_pkt(tlv_pkt_t *tlv_pkt, int c2_api_call_status)
{
    tlv_pkt_t *tlv_packet = calloc(1, sizeof(*tlv_packet));

    tlv_pkt_new->channel = tlv_pkt->channel;
    tlv_pkt_new->pool = tlv_pkt->pool;
    tlv_pkt_new->tag = tlv_pkt->tag;
    tlv_pkt_new->status = status;
    tlv_pkt_new->data = NULL;
    tlv_pkt_new->size = 0;

    return tlv_packet;
}

/*
 * Craft C2 API call packet from existing C2 TLV packet and result.
 */

void craft_c2_tlv_pkt(tlv_pkt_t *tlv_pkt, int c2_status, char *c2_result)
{
    tlv_pkt->status = c2_status;
    tlv_data_free(tlv_pkt);

    if (c2_result != NULL)
    {
        size_t length = strlen(c2_result);
        char *c2_result_msg = malloc(length + 1);

        strncpy(c2_result_msg, c2_result, length);
        c2_result_msg[length] = '\0';

        tlv_pkt->data = c2_result_msg;
        tlv_pkt->size = length + 1;
    } else
    {
        tlv_pkt->data = NULL;
        tlv_pkt->size = 0;
    }
}

/*
 * Register C2 API calls and save them to the C2 API calls table.
 */

void c2_register_api_calls(c2_api_calls_t **c2_api_calls)
{
    register_api_calls(c2_api_calls);
}

/*
 * Register C2 API calls pool and connect C2 API calls table to it.
 */

static void c2_register_api_calls_pool(c2_api_calls_t **c2_api_calls, int c2_pool)
{
    c2_api_calls_t *c2_api_call;
    HASH_FIND_INT(*c2_api_calls, &c2_pool, c2_api_call);

    if (c2_api_call == NULL)
    {
        c2_api_calls_t *c2_api_call_new = calloc(1, sizeof(*c2_api_call_new));

        if (c2_api_call_new != NULL)
        {
            c2_api_call_new->pool = c2_pool;
            c2_api_call_new->handlers = NULL;

            HASH_ADD_INT(*c2_api_calls, c2_pool, c2_api_call_new);
            log_debug("* Registered C2 API call pool (%d)\n", c2_pool);
        }
    }
}

/*
 * Register C2 API calls tag.
 */

static void c2_register_api_calls_tag(c2_api_calls_t **c2_api_calls, int c2_pool,
                                      int c2_tag, c2_api_t c2_handler)
{
    c2_api_calls_t *c2_api_call;
    HASH_FIND_INT(*c2_api_calls, &c2_pool, c2_api_call);

    if (c2_api_call != NULL)
    {
        c2_api_call_handlers_t *c2_api_call_handler;
        HASH_FIND_INT(c2_api_call->handlers, &c2_tag, c2_api_call_handler);

        if (c2_api_call_handler == NULL)
        {
            c2_api_call_handlers_t *c2_api_call_handler_new = calloc(1, sizeof(*c2_api_call_handler_new));

            if (c2_api_call_handler_new != NULL)
            {
                c2_api_call_handler_new->tag = c2_tag;
                c2_api_call_handler_new->handler = c2_handler;

                HASH_ADD_INT(c2_api_call->handlers, c2_tag, c2_api_call_handler_new);
                log_debug("* Registered C2 API call (%d)\n", c2_tag);
            }
        }
    }
}

/*
 * Register C2 API call.
 */

void c2_register_api_call(c2_api_calls_t **c2_api_calls, int c2_tag,
                          c2_api_t c2_handler, int c2_pool)
{
    c2_register_api_calls_pool(c2_api_calls, c2_pool);
    c2_register_api_calls_tag(c2_api_calls, c2_pool, c2_tag, c2_handler);
}

/*
 * Make C2 API call.
 */

tlv_pkt_t *c2_make_api_call(c2_api_calls_t **c2_api_calls, tlv_pkt_t *tlv_pkt)
{
    c2_api_calls_t *c2_api_call;

    log_debug("* Looking for C2 API call pool (%d)\n", tlv_pkt->pool);
    HASH_FIND_INT(*c2_api_calls, &tlv_pkt->pool, c2_api_call);

    if (c2_api_call == NULL)
    {
        log_debug("* C2 API call pool was not found (%d)\n", tlv_pkt->pool);
        return NULL;
    }

    c2_api_call_handlers_t *c2_api_call_handler;

    log_debug("* Looking for C2 API call (%d)\n", tlv_pkt->tag);
    HASH_FIND_INT(c2_api_call->handlers, &tlv_pkt->tag, c2_api_call_handler);

    if (c2_api_call_handler == NULL)
    {
        log_debug("* C2 API call was not found (%d)\n", tlv_pkt->tag);
        return NULL;
    }

    return c2_api_call_handler->handler(tlv_pkt);
}

/*
 * Free whole C2 API calls table.
 */

void c2_api_calls_free(c2_api_calls_t *c2_api_calls)
{
    c2_api_calls_t *c2_api_call;

    for (c2_api_call = c2_api_calls; c2_api_call != NULL; c2_api_call = c2_api_call->hh.next)
    {
        c2_api_call_handlers_t *c2_handler;

        for (c2_handler = c2_api_calls->handlers; c2_handler != NULL; c2_handler = c2_handler->hh.next)
        {
            log_debug("* Freed C2 API call (%d)\n", c2_handler->tag);

            HASH_DEL(c2_api_calls->handlers, c2_handler);
            free(c2_handler);
        }

        log_debug("* Freed C2 API call pool (%d)\n", c2->pool);

        HASH_DEL(c2_api_calls, c2_api_call);

        free(c2_api_call->handlers);
        free(c2_api_call);
    }

    free(c2_api_calls);
}
