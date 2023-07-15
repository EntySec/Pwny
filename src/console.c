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
#include <tab.h>
#include <log.h>

#include <stdio.h>
#include <stdlib.h>

/*
 * Run TLV console loop which reads commands repeatedly.
 */

void tlv_console_loop(tlv_pkt_t *tlv_packet)
{
    c2_api_calls_t *c2_api_calls_table = NULL;
    c2_register_api_calls(&c2_api_calls_table);

    tabs_t *tabs_table = NULL;
    net_nodes_t *net_nodes_table = NULL;

    int net_nodes_id = 0;

    for (;;)
    {
        tlv_pkt_t *tlv_result;
        tlv_channel_read(tlv_packet, TLV_NULL);

        log_debug("* Talking to %d for now from base\n", tlv_packet->tlv_pkt_channel);

        if (tlv_packet->tlv_pkt_pool == API_POOL_BUILTINS)
        {
            if (tlv_packet->tlv_pkt_tag == API_QUIT)
            {
                tlv_result = create_c2_tlv_pkt(tlv_packet, API_CALL_SUCCESS);
                tlv_channel_send(tlv_result);

                tlv_pkt_free(tlv_result);
                break;
            }

            if (tlv_packet->tlv_pkt_tag == API_ADD_NODE)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_packet, &tlv_argv, 4, TLV_NO_NULL);

                net_node_t net_node_new = {
                    .net_node_src_host = UNPACK_INT(tlv_argv[0]->tlv_pkt_data),
                    .net_node_src_port = UNPACK_INT(tlv_argv[1]->tlv_pkt_data),
                    .net_node_dst_host = UNPACK_INT(tlv_argv[2]->tlv_pkt_data),
                    .net_node_dst_port = UNPACK_INT(tlv_argv[3]->tlv_pkt_data),
                };

                net_nodes_add(&net_nodes_table, net_nodes_id, net_node_new);
                net_nodes_id += 1;

                tlv_argv_free(tlv_argv, 4);

            } else if (tlv_packet->tlv_pkt_tag == API_DEL_NODE)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_packet, &tlv_argv, 1, TLV_NO_NULL);

                net_nodes_delete(&net_nodes_table, UNPACK_INT(tlv_argv[0]->tlv_pkt_data));
                tlv_argv_free(tlv_argv, 1);

            } else if (tlv_packet->tlv_pkt_tag == API_ADD_TAB)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_packet, &tlv_argv, 2, TLV_NO_NULL);

                tab_add(&tabs_table, UNPACK_INT(tlv_argv[0]->tlv_pkt_data), tlv_argv[1]->tlv_pkt_data);
                tlv_argv_free(tlv_argv, 1);

            } else if (tlv_packet->tlv_pkt_tag == API_DEL_TAB)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_packet, &tlv_argv, 1, TLV_NO_NULL);

                tab_delete(&tabs_table, UNPACK_INT(tlv_argv[0]->tlv_pkt_data));
                tlv_argv_free(tlv_argv, 1);
            }

            tlv_result = create_c2_tlv_pkt(tlv_packet, API_CALL_SUCCESS);
            tlv_channel_send(tlv_result);

            tlv_pkt_free(tlv_result);
            continue;
        }

        tlv_result = c2_make_api_call(&c2_api_calls_table, tlv_packet);

        if (tlv_result != NULL)
        {
            tlv_channel_send(tlv_result);
        } else
        {
            if (tab_lookup(&tabs_table, tlv_packet->tlv_pkt_pool, tlv_packet) < 0)
            {
                tlv_result = create_c2_tlv_pkt(tlv_packet, API_CALL_NOT_IMPLEMENTED);
                tlv_channel_send(tlv_result);
            }
        }

        tlv_pkt_free(tlv_result);
    }

    net_nodes_free(net_nodes_table);
    tabs_free(tabs_table);

    c2_api_calls_free(c2_api_calls_table);
}

/*
 * Run TLV tab loop which reads commands repeatedly.
 */

void tab_console_loop(c2_api_calls_t *c2_api_calls_table)
{
    tlv_pkt_t *tlv_packet = tlv_channel_pkt(TLV_NO_CHANNEL);

    for (;;)
    {
        tlv_channel_read_fd(STDIN_FILENO, tlv_packet, TLV_NULL);
        log_debug("* Talking to %d for now from tab\n", tlv_packet->tlv_pkt_channel);

        if (tlv_packet->tlv_pkt_tag == API_QUIT)
            break;

        tlv_pkt_t *tlv_result = c2_make_api_call(&c2_api_calls_table, tlv_packet);

        if (tlv_result != NULL)
        {
            tlv_channel_send(tlv_result);

            log_debug("* Tab forced to (pool: %d, tag: %d, fd: %d)\n", tlv_result->tlv_pkt_pool,
                      tlv_result->tlv_pkt_tag, tlv_result->tlv_pkt_channel);

        } else
        {
            tlv_result = create_c2_tlv_pkt(tlv_packet, API_CALL_NOT_IMPLEMENTED);

            tlv_channel_send(tlv_result);
        }

        tlv_data_free(tlv_result);
    }

    tlv_pkt_free(tlv_packet);
}
