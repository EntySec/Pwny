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

#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <api.h>
#include <c2.h>
#include <node.h>
#include <tlv_types.h>
#include <tlv.h>

#define NET_BASE 3

#define NET_ADD_NODE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL)
#define NET_DELETE_NODE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NET_BASE, \
                       API_CALL + 1)

static tlv_pkt_t *net_add_node(c2_t *c2)
{
    ipv4_t src_host;
    ipv4_t dst_host;
    port_t src_port;
    port_t dst_port;

    tlv_pkt_t *result;

    tlv_pkt_get_uint(c2->request, TLV_TYPE_NODE_SRC_ADDR, &src_host);
    tlv_pkt_get_ushort(c2->request, TLV_TYPE_NODE_SRC_PORT, &src_port);
    tlv_pkt_get_uint(c2->request, TLV_TYPE_NODE_DST_ADDR, &dst_host);
    tlv_pkt_get_ushort(c2->request, TLV_TYPE_NODE_DST_PORT, &dst_port);

    if (node_add(&c2->dynamic.nodes, c2->dynamic.n_count, \
        src_host, src_port, dst_host, dst_port) >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS);
        tlv_pkt_add_int(result, TLV_TYPE_NODE_ID, c2->dynamic.n_count);
        c2->dynamic.n_count++;
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *net_delete_node(c2_t *c2)
{
    int node_id;

    tlv_pkt_get_int(c2->request, TLV_TYPE_NODE_ID, &node_id);

    if (node_delete(&c2->dynamic.nodes, node_id) >= 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

void register_net_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, NET_ADD_NODE, net_add_node);
    api_call_register(api_calls, NET_DELETE_NODE, net_delete_node);
}

#endif
