/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

#ifndef _IFCONFIG_H_
#define _IFCONFIG_H_

#include <stdlib.h>
#include <string.h>
#include <sigar.h>
#include <sigar_format.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define IFCONFIG_BASE 13

#define IFCONFIG_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       IFCONFIG_BASE, \
                       API_CALL)

#define TLV_TYPE_IF_NAME    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE)
#define TLV_TYPE_IF_ADDR    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 1)
#define TLV_TYPE_IF_MASK    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 2)
#define TLV_TYPE_IF_BCAST   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 3)
#define TLV_TYPE_IF_HWADDR  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 4)
#define TLV_TYPE_IF_ADDR6   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, IFCONFIG_BASE, API_TYPE + 5)
#define TLV_TYPE_IF_FLAGS   TLV_TYPE_CUSTOM(TLV_TYPE_INT, IFCONFIG_BASE, API_TYPE)
#define TLV_TYPE_IF_MTU     TLV_TYPE_CUSTOM(TLV_TYPE_INT, IFCONFIG_BASE, API_TYPE + 1)
#define TLV_TYPE_IF_GROUP   TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, IFCONFIG_BASE, API_TYPE)

static tlv_pkt_t *ifconfig_list(c2_t *c2)
{
    int status;
    unsigned long i;
    core_t *core;
    tlv_pkt_t *result;
    sigar_net_interface_list_t iflist;

    core = c2->data;

    status = sigar_net_interface_list_get(core->sigar, &iflist);
    if (status != SIGAR_OK)
    {
        log_debug("* Failed to get interface list (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < iflist.number; i++)
    {
        sigar_net_interface_config_t ifcfg;
        tlv_pkt_t *entry;
        char addr_buf[SIGAR_INET6_ADDRSTRLEN];

        status = sigar_net_interface_config_get(core->sigar, iflist.data[i], &ifcfg);
        if (status != SIGAR_OK)
        {
            continue;
        }

        entry = tlv_pkt_create();
        tlv_pkt_add_string(entry, TLV_TYPE_IF_NAME, ifcfg.name);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &ifcfg.address, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_IF_ADDR, addr_buf);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &ifcfg.netmask, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_IF_MASK, addr_buf);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &ifcfg.broadcast, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_IF_BCAST, addr_buf);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &ifcfg.hwaddr, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_IF_HWADDR, addr_buf);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &ifcfg.address6, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_IF_ADDR6, addr_buf);

        tlv_pkt_add_u32(entry, TLV_TYPE_IF_FLAGS, (int32_t)ifcfg.flags);
        tlv_pkt_add_u32(entry, TLV_TYPE_IF_MTU, (int32_t)ifcfg.mtu);

        tlv_pkt_add_tlv(result, TLV_TYPE_IF_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    sigar_net_interface_list_destroy(core->sigar, &iflist);

    return result;
}

void register_ifconfig_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, IFCONFIG_LIST, ifconfig_list);
}

#endif
