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

#ifndef _NETSTAT_H_
#define _NETSTAT_H_

#include <stdlib.h>
#include <string.h>
#include <sigar.h>
#include <sigar_format.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define NETSTAT_BASE 14

#define NETSTAT_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       NETSTAT_BASE, \
                       API_CALL)

#define TLV_TYPE_CONN_PROTO     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE)
#define TLV_TYPE_CONN_LADDR    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE + 1)
#define TLV_TYPE_CONN_RADDR    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE + 2)
#define TLV_TYPE_CONN_STATE    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, NETSTAT_BASE, API_TYPE + 3)
#define TLV_TYPE_CONN_LPORT    TLV_TYPE_CUSTOM(TLV_TYPE_INT, NETSTAT_BASE, API_TYPE)
#define TLV_TYPE_CONN_RPORT    TLV_TYPE_CUSTOM(TLV_TYPE_INT, NETSTAT_BASE, API_TYPE + 1)
#define TLV_TYPE_CONN_PID      TLV_TYPE_CUSTOM(TLV_TYPE_INT, NETSTAT_BASE, API_TYPE + 2)
#define TLV_TYPE_CONN_GROUP    TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, NETSTAT_BASE, API_TYPE)

static const char *tcp_state_name(int state)
{
    switch (state)
    {
        case SIGAR_TCP_ESTABLISHED: return "ESTABLISHED";
        case SIGAR_TCP_SYN_SENT:   return "SYN_SENT";
        case SIGAR_TCP_SYN_RECV:   return "SYN_RECV";
        case SIGAR_TCP_FIN_WAIT1:  return "FIN_WAIT1";
        case SIGAR_TCP_FIN_WAIT2:  return "FIN_WAIT2";
        case SIGAR_TCP_TIME_WAIT:  return "TIME_WAIT";
        case SIGAR_TCP_CLOSE:      return "CLOSE";
        case SIGAR_TCP_CLOSE_WAIT: return "CLOSE_WAIT";
        case SIGAR_TCP_LAST_ACK:   return "LAST_ACK";
        case SIGAR_TCP_LISTEN:     return "LISTEN";
        case SIGAR_TCP_CLOSING:    return "CLOSING";
        case SIGAR_TCP_IDLE:       return "IDLE";
        case SIGAR_TCP_BOUND:      return "BOUND";
        default:                   return "UNKNOWN";
    }
}

static tlv_pkt_t *netstat_list(c2_t *c2)
{
    int status;
    unsigned long i;
    core_t *core;
    tlv_pkt_t *result;
    sigar_net_connection_list_t connlist;
    int flags;

    core = c2->data;

    if (core->sigar == NULL)
    {
        log_debug("* Sigar not initialized\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    flags = SIGAR_NETCONN_CLIENT | SIGAR_NETCONN_SERVER |
            SIGAR_NETCONN_TCP | SIGAR_NETCONN_UDP;

    status = sigar_net_connection_list_get(core->sigar, &connlist, flags);
    if (status != SIGAR_OK)
    {
        log_debug("* Failed to get connection list (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < connlist.number; i++)
    {
        sigar_net_connection_t *conn = &connlist.data[i];
        tlv_pkt_t *entry;
        char addr_buf[SIGAR_INET6_ADDRSTRLEN];
        const char *proto;

        entry = tlv_pkt_create();

        if (conn->type == SIGAR_NETCONN_TCP)
        {
            proto = "tcp";
        }
        else if (conn->type == SIGAR_NETCONN_UDP)
        {
            proto = "udp";
        }
        else
        {
            proto = "raw";
        }

        tlv_pkt_add_string(entry, TLV_TYPE_CONN_PROTO, (char *)proto);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &conn->local_address, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_CONN_LADDR, addr_buf);
        tlv_pkt_add_u32(entry, TLV_TYPE_CONN_LPORT, (int32_t)conn->local_port);

        memset(addr_buf, 0, sizeof(addr_buf));
        sigar_net_address_to_string(core->sigar, &conn->remote_address, addr_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_CONN_RADDR, addr_buf);
        tlv_pkt_add_u32(entry, TLV_TYPE_CONN_RPORT, (int32_t)conn->remote_port);

        tlv_pkt_add_string(entry, TLV_TYPE_CONN_STATE, (char *)tcp_state_name(conn->state));
        tlv_pkt_add_u32(entry, TLV_TYPE_CONN_PID, (int32_t)conn->pid);

        tlv_pkt_add_tlv(result, TLV_TYPE_CONN_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    sigar_net_connection_list_destroy(core->sigar, &connlist);

    return result;
}

void register_netstat_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, NETSTAT_LIST, netstat_list);
}

#endif
