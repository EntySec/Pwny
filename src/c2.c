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
 * Craft TLV transport packet from primary TLV transport packet
 * and C2 API call packet.
 */

tlv_pkt_t craft_c2_tlv_pkt(tlv_pkt_t tlv_packet, c2_api_call_t *c2_api_call_new)
{
    tlv_pkt_t c2_tlv_pkt = {
        .tlv_pkt_channel = tlv_packet.tlv_pkt_channel,
        .tlv_pkt_pool = c2_api_call_new->c2_api_call_pool,
        .tlv_pkt_tag = c2_api_call_new->c2_api_call_tag,
        .tlv_pkt_status = c2_api_call_new->c2_api_call_status,
        .tlv_pkt_size = strlen(c2_api_call_new->c2_api_call_result) + 1,
        .tlv_pkt_data = c2_api_call_new->c2_api_call_result,
    };

    return c2_tlv_pkt;
}

/*
 * Craft C2 API call packet from primary TLV transport packet
 * and C2 API call status and result.
 */

c2_api_call_t *craft_c2_api_call_pkt(tlv_pkt_t tlv_packet, int c2_api_call_status,
                                     char *c2_api_call_result)
{
    c2_api_call_t *c2_api_call_new = calloc(1, sizeof(*c2_api_call_new));

    c2_api_call_new->c2_api_call_pool = tlv_packet.tlv_pkt_pool;
    c2_api_call_new->c2_api_call_tag = tlv_packet.tlv_pkt_tag;
    c2_api_call_new->c2_api_call_status = c2_api_call_status;
    c2_api_call_new->c2_api_call_result = strdup(c2_api_call_result);

    return c2_api_call_new;
}

/*
 * Append string to the C2 API call packet.
 */

void c2_add_str(c2_api_call_t *c2_api_call_new, char *c2_str)
{
    size_t str_len = strlen(c2_str) + 1;
    size_t result_len = strlen(c2_api_call_new->c2_api_call_result) + 1;

    char result[str_len + result_len];
    snprintf(result, sizeof(result), "%s%s", c2_api_call_new->c2_api_call_result, c2_str);

    c2_api_call_new->c2_api_call_result = result;
}

/*
 * Register C2 API calls and save them to the C2 API calls table.
 */

void c2_register_api_calls(c2_api_calls_t **c2_api_calls_table)
{
    register_api_calls(c2_api_calls_table);
}

/*
 * Register C2 API calls pool and connect C2 API calls table to it.
 */

static void c2_register_api_calls_pool(c2_api_calls_t **c2_api_calls_table, int c2_api_call_pool)
{
    c2_api_calls_t *c2_api_calls_new;
    HASH_FIND_INT(*c2_api_calls_table, &c2_api_call_pool, c2_api_calls_new);

    if (c2_api_calls_new == NULL)
    {
        c2_api_calls_t *c2_api_calls_table_new = calloc(1, sizeof(*c2_api_calls_table_new));

        if (c2_api_calls_table_new != NULL)
        {
            c2_api_calls_table_new->c2_api_call_pool = c2_api_call_pool;
            c2_api_calls_table_new->c2_api_call_plugin = NULL;
            c2_api_calls_table_new->c2_api_call_handlers = NULL;

            HASH_ADD_INT(*c2_api_calls_table, c2_api_call_pool, c2_api_calls_table_new);
            log_debug("* Registered C2 API call pool (%d)\n", c2_api_call_pool);
        }
    }
}

/*
 * Register C2 API calls tag.
 */

static void c2_register_api_calls_tag(c2_api_calls_t **c2_api_calls_table, int c2_api_call_pool,
                                      int c2_api_call_tag, c2_api_t c2_api_call_handler)
{
    c2_register_api_calls_pool(c2_api_calls_table, c2_api_call_pool);

    c2_api_calls_t *c2_api_calls_new;
    HASH_FIND_INT(*c2_api_calls_table, &c2_api_call_pool, c2_api_calls_new);

    if (c2_api_calls_new != NULL)
    {
        c2_api_call_handlers_t *c2_api_call_handler_new;
        HASH_FIND_INT(c2_api_calls_new->c2_api_call_handlers, &c2_api_call_tag, c2_api_call_handler_new);

        if (c2_api_call_handler_new == NULL)
        {
            c2_api_call_handlers_t *c2_api_call_handlers_new = calloc(1, sizeof(*c2_api_call_handlers_new));

            if (c2_api_call_handlers_new != NULL)
            {
                c2_api_call_handlers_new->c2_api_call_tag = c2_api_call_tag;
                c2_api_call_handlers_new->c2_api_call_handler = c2_api_call_handler;

                HASH_ADD_INT(c2_api_calls_new->c2_api_call_handlers, c2_api_call_tag, c2_api_call_handlers_new);
                log_debug("* Registered C2 API call (%d)\n", c2_api_call_tag);
            }
        }
    }
}

/*
 * Register C2 API call.
 */

void c2_register_api_call(c2_api_calls_t **c2_api_calls_table,
                          int c2_api_call_tag, c2_api_t c2_api_call_handler,
                          int c2_api_call_pool)
{
    c2_register_api_calls_tag(c2_api_calls_table, c2_api_call_pool,
                              c2_api_call_tag, c2_api_call_handler);
}

c2_api_call_t *c2_make_api_call(c2_api_calls_t **c2_api_calls_table,
                               tlv_pkt_t tlv_packet)
{
    c2_api_calls_t *c2_api_calls_new;

    log_debug("* Looking for C2 API call pool (%d)\n", tlv_packet.tlv_pkt_pool);
    HASH_FIND_INT(*c2_api_calls_table, &tlv_packet.tlv_pkt_pool, c2_api_calls_new);

    if (c2_api_calls_new == NULL)
    {
        log_debug("* C2 API call pool was not found (%d)\n", tlv_packet.tlv_pkt_pool);
        return NULL;
    }

    c2_api_call_handlers_t *c2_api_call_handlers_new;

    log_debug("* Looking for C2 API call (%d)\n", tlv_packet.tlv_pkt_tag);
    HASH_FIND_INT(c2_api_calls_new->c2_api_call_handlers, &tlv_packet.tlv_pkt_tag, c2_api_call_handlers_new);

    if (c2_api_call_handlers_new == NULL)
    {
        log_debug("* C2 API call was not found (%d)\n", tlv_packet.tlv_pkt_tag);
        return NULL;
    }

    return c2_api_call_handlers_new->c2_api_call_handler(tlv_packet);
}

/*
 * Free single C2 API call.
 */

void c2_api_call_free(c2_api_call_t *c2_api_call_new)
{
    free(c2_api_call_new);
}

/*
 * Free whole C2 API calls table.
 */

void c2_api_calls_free(c2_api_calls_t *c2_api_calls_new)
{
    c2_api_calls_t *c2;

    for (c2 = c2_api_calls_new; c2 != NULL; c2 = c2->hh.next)
    {
        c2_api_call_handlers_t *c2_handler;

        for (c2_handler = c2_api_calls_new->c2_api_call_handlers; c2_handler != NULL; c2_handler = c2_handler->hh.next)
        {
            log_debug("* Freed C2 API call (%d)\n", c2_handler->c2_api_call_tag);

            HASH_DEL(c2_api_calls_new->c2_api_call_handlers, c2_handler);
            free(c2_handler);
        }

        log_debug("* Freed C2 API call pool (%d)\n", c2->c2_api_call_pool);

        HASH_DEL(c2_api_calls_new, c2);

        free(c2->c2_api_call_handlers);
        free(c2);
    }

    free(c2_api_calls_new);
}
