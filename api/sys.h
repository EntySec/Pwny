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

#include <c2.h>
#include <tlv.h>

static c2_api_call_t *sys_test(tlv_pkt_t tlv_packet)
{
    return craft_c2_api_call_pkt(tlv_packet, API_CALL_SUCCESS, "Test");
}

static c2_api_call_t *sys_push(tlv_pkt_t tlv_packet)
{
    tlv_pkt_t *tlv_argv;
    tlv_argv_read(tlv_packet.tlv_pkt_channel, &tlv_argv, 2, TLV_NULL);

    tlv_file_t tlv_file_new = {
        .tlv_file_to = tlv_argv[0].tlv_pkt_data,
        .tlv_file_from = tlv_argv[1].tlv_pkt_data,
    };

    if (tlv_channel_read_file(tlv_packet, tlv_file_new) < 0)
    {
        tlv_argv_free(tlv_argv, 2);
        return craft_c2_api_call_pkt(tlv_packet, API_CALL_RW_ERROR, "");
    }

    tlv_argv_free(tlv_argv, 2);
    return NULL;
}

static c2_api_call_t *sys_pull(tlv_pkt_t tlv_packet)
{
    tlv_pkt_t *tlv_argv;
    tlv_argv_read(tlv_packet.tlv_pkt_channel, &tlv_argv, 2, TLV_NULL);

    tlv_file_t tlv_file_new = {
        .tlv_file_to = tlv_argv[0].tlv_pkt_data,
        .tlv_file_from = tlv_argv[1].tlv_pkt_data,
    };

    if (tlv_channel_send_file(tlv_packet, tlv_file_new) < 0)
    {
        tlv_argv_free(tlv_argv, 2);
        return craft_c2_api_call_pkt(tlv_packet, API_CALL_RW_ERROR, "");
    }

    tlv_argv_free(tlv_argv, 2);
    return craft_c2_api_call_pkt(tlv_packet, API_CALL_SUCCESS, "");
}

void register_sys_api_calls(c2_api_calls_t **c2_api_calls_table)
{
    c2_register_api_call(c2_api_calls_table, API_CALL, sys_test, API_POOL_PEX);
    c2_register_api_call(c2_api_calls_table, API_CALL + 1, sys_push, API_POOL_PEX);
    c2_register_api_call(c2_api_calls_table, API_CALL + 2, sys_pull, API_POOL_PEX);
}