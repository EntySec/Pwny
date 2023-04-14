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

#define _DEFAULT_SOURCE

#include <string.h>
#include <stdlib.h>
#include <string.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "c2.h"
#include "tlv.h"
#include "log.h"
#include "calls.h"

#include "uthash/uthash.h"

tlv_transport_pkt_t craft_c2_tlv_pkt(tlv_transport_pkt_t tlv_transport_packet, c2_api_call_t *c2_api_call_new)
{
    tlv_transport_pkt_t c2_tlv_pkt = {
        .tlv_transport_pkt_channel = tlv_transport_packet.tlv_transport_pkt_channel,
        .tlv_transport_pkt_scope = c2_api_call_new->c2_api_call_scope,
        .tlv_transport_pkt_tag = c2_api_call_new->c2_api_call_tag,
        .tlv_transport_pkt_status = c2_api_call_new->c2_api_call_status,
        .tlv_transport_pkt_size = strlen(c2_api_call_new->c2_api_call_result),
        .tlv_transport_pkt_data = c2_api_call_new->c2_api_call_result,
    };

    return c2_tlv_pkt;
}

c2_api_call_t *craft_c2_api_call_pkt(tlv_transport_pkt_t tlv_transport_packet, int c2_api_call_status,
                                     char *c2_api_call_result)
{
    c2_api_call_t *c2_api_call_new = calloc(1, sizeof(*c2_api_call_new));

    c2_api_call_new->c2_api_call_scope = tlv_transport_packet.tlv_transport_pkt_scope;
    c2_api_call_new->c2_api_call_tag = tlv_transport_packet.tlv_transport_pkt_tag;
    c2_api_call_new->c2_api_call_status = c2_api_call_status;
    c2_api_call_new->c2_api_call_result = strdup(c2_api_call_result);

    return c2_api_call_new;
}

tlv_transport_pkt_t c2_add_str(tlv_transport_pkt_t tlv_transport_packet, char *c2_str)
{
    size_t str_len = strlen(c2_str) + 1;
    size_t result_len = strlen(tlv_transport_packet.tlv_transport_pkt_data) + 1;

    char result[str_len + result_len];
    snprintf(result, sizeof(result), "%s%s", tlv_transport_packet.tlv_transport_pkt_data, c2_str);

    tlv_transport_packet.tlv_transport_pkt_data = result;
    return tlv_transport_packet;
}

void c2_register_api_calls(c2_api_calls_t **c2_api_calls_table)
{
    register_api_calls(c2_api_calls_table);
}

int c2_unload_api_calls(c2_api_calls_t **c2_api_calls_table, int c2_api_call_scope)
{
    c2_api_calls_t *c2_api_calls_new;
    HASH_FIND_INT(*c2_api_calls_table, &c2_api_call_scope, c2_api_calls_new);

    if (c2_api_calls_new->c2_api_call_plugin != NULL)
    {
        c2_api_call_handlers_t *c2;

        for (c2 = c2_api_calls_new->c2_api_call_handlers; c2 != NULL; c2 = c2->hh.next)
        {
            log_debug("* Unloaded api call (%d)\n", c2->c2_api_call_tag);

            HASH_DEL(c2_api_calls_new->c2_api_call_handlers, c2);
            free(c2);
        }

        #ifdef WINDOWS
        FreeLibrary(c2_api_calls_new->c2_api_call_plugin);
        c2_api_calls_new->c2_api_call_plugin = NULL;
        #else
        dlclose(c2_api_calls_new->c2_api_call_plugin);
        #endif

        HASH_DEL(*c2_api_calls_table, c2_api_calls_new);

        free(c2_api_calls_new->c2_api_call_handlers);
        free(c2_api_calls_new);

        log_debug("* Unloaded plugin call scope (%d)\n", c2_api_call_scope);
        return 0;
    }

    return -1;
}

int c2_load_api_calls(c2_api_calls_t **c2_api_calls_table, char *plugin)
{
    int (*load_api_calls)(c2_api_calls_t **);

    #ifdef WINDOWS
    void *c2_api_call_plugin = LoadLibraryA(plugin);

    if (!c2_api_call_plugin)
        return -1;

    *(FARPROC *)(&load_api_calls) = GetProcAddress(c2_api_call_plugin, "load_api_calls");
    if (!load_api_calls)
        return -1;

    #else
    void *c2_api_call_plugin = dlopen(plugin, RTLD_LAZY);
    char *error;

    if (!c2_api_call_plugin)
        return -1;

    dlerror();

    *(void **)(&load_api_calls) = dlsym(c2_api_call_plugin, "load_api_calls");
    if ((error = dlerror()) != NULL)
        return -1;
    #endif

    int c2_api_call_scope = (*load_api_calls)(c2_api_calls_table);

    c2_api_calls_t *c2_api_calls_new;
    HASH_FIND_INT(*c2_api_calls_table, &c2_api_call_scope, c2_api_calls_new);

    c2_api_calls_new->c2_api_call_plugin = c2_api_call_plugin;
    log_debug("* Loaded plugin call scope (%d)\n", c2_api_call_scope);

    return 0;
}

static void c2_register_api_calls_scope(c2_api_calls_t **c2_api_calls_table, int c2_api_call_scope)
{
    c2_api_calls_t *c2_api_calls_new;
    HASH_FIND_INT(*c2_api_calls_table, &c2_api_call_scope, c2_api_calls_new);

    if (c2_api_calls_new == NULL)
    {
        c2_api_calls_t *c2_api_calls_table_new = calloc(1, sizeof(*c2_api_calls_table_new));

        if (c2_api_calls_table_new != NULL)
        {
            c2_api_calls_table_new->c2_api_call_scope = c2_api_call_scope;
            c2_api_calls_table_new->c2_api_call_plugin = NULL;
            c2_api_calls_table_new->c2_api_call_handlers = NULL;

            HASH_ADD_INT(*c2_api_calls_table, c2_api_call_scope, c2_api_calls_table_new);
            log_debug("* Registered C2 API call scope (%d)\n", c2_api_call_scope);
        }
    }
}

static void c2_register_api_calls_tag(c2_api_calls_t **c2_api_calls_table, int c2_api_call_scope,
                                      int c2_api_call_tag, c2_api_t c2_api_call_handler)
{
    c2_register_api_calls_scope(c2_api_calls_table, c2_api_call_scope);

    c2_api_calls_t *c2_api_calls_new;
    HASH_FIND_INT(*c2_api_calls_table, &c2_api_call_scope, c2_api_calls_new);

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

void c2_register_api_call(c2_api_calls_t **c2_api_calls_table,
                          int c2_api_call_tag, c2_api_t c2_api_call_handler,
                          int c2_api_call_scope)
{
    c2_register_api_calls_tag(c2_api_calls_table, c2_api_call_scope,
                              c2_api_call_tag, c2_api_call_handler);
}

c2_api_call_t *c2_make_api_call(c2_api_calls_t **c2_api_calls_table,
                               tlv_transport_pkt_t tlv_transport_packet)
{
    c2_api_calls_t *c2_api_calls_new;

    log_debug("* Looking for C2 API call scope (%d)\n", tlv_transport_packet.tlv_transport_pkt_scope);
    HASH_FIND_INT(*c2_api_calls_table, &tlv_transport_packet.tlv_transport_pkt_scope, c2_api_calls_new);

    if (c2_api_calls_new == NULL)
    {
        log_debug("* C2 API call scope was not found (%d)\n", tlv_transport_packet.tlv_transport_pkt_scope);
        return NULL;
    }

    c2_api_call_handlers_t *c2_api_call_handlers_new;

    log_debug("* Looking for C2 API call (%d)\n", tlv_transport_packet.tlv_transport_pkt_tag);
    HASH_FIND_INT(c2_api_calls_new->c2_api_call_handlers, &tlv_transport_packet.tlv_transport_pkt_tag, c2_api_call_handlers_new);

    if (c2_api_call_handlers_new == NULL)
    {
        log_debug("* C2 API call was not found (%d)\n", tlv_transport_packet.tlv_transport_pkt_tag);
        return NULL;
    }

    return c2_api_call_handlers_new->c2_api_call_handler(tlv_transport_packet);
}

void c2_api_call_free(c2_api_call_t *c2_api_call_new)
{
    free(c2_api_call_new);
}

void c2_api_calls_free(c2_api_calls_t *c2_api_calls_new)
{
    c2_api_calls_t *c2;

    for (c2 = c2_api_calls_new; c2 != NULL; c2 = c2->hh.next)
    {
        if (c2->c2_api_call_plugin != NULL)
            c2_unload_api_calls(&c2_api_calls_new, c2->c2_api_call_scope);
        else
        {
            c2_api_call_handlers_t *c2_handler;

            for (c2_handler = c2_api_calls_new->c2_api_call_handlers; c2_handler != NULL; c2_handler = c2_handler->hh.next)
            {
                log_debug("* Freed C2 API call (%d)\n", c2_handler->c2_api_call_tag);

                HASH_DEL(c2_api_calls_new->c2_api_call_handlers, c2_handler);
                free(c2_handler);
            }

            log_debug("* Freed C2 API call scope (%d)\n", c2->c2_api_call_scope);

            HASH_DEL(c2_api_calls_new, c2);

            free(c2->c2_api_call_handlers);
            free(c2);
        }
    }

    free(c2_api_calls_new);
}
