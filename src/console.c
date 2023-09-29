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
#include <api.h>
#include <c2.h>
#include <node.h>
#include <migrate.h>
#include <tab.h>
#include <log.h>
#include <tlv_types.h>

#include <stdio.h>
#include <stdlib.h>

void tlv_console_loop(c2_t *c2)
{
    int tag;
    int status;
    int tab_id;

    tlv_pkt_t *tlv_pkt;

    api_calls_register(&c2->dynamic.api_calls);

    for (;;)
    {
        c2_read(c2);

        log_debug("* Talking to %d from base\n", c2->fd);
        tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_TAG, &tag);

        if ((tlv_pkt = api_call_make(&c2->dynamic.api_calls, c2, tag)) == NULL)
        {
            if (tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_TAB_ID, &tab_id) == 0)
                if ((tlv_pkt = tab_lookup(&c2->dynamic.tabs, tab_id, c2)) == NULL)
                    tlv_pkt = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);
            else
                tlv_pkt = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);
        }

        c2_write(c2, tlv_pkt);

        if (tlv_pkt_get_int(tlv_pkt, TLV_TYPE_STATUS, &status) == 0)
        {
            if (status == API_CALL_QUIT)
            {
                tlv_pkt_destroy(tlv_pkt);
                tlv_pkt_destroy(c2->tlv_pkt);

                break;
            }
        }

        tlv_pkt_destroy(tlv_pkt);
        tlv_pkt_destroy(c2->tlv_pkt);
    }
}

void tab_console_loop(c2_t *c2)
{
    int tag;
    tlv_pkt_t *tlv_pkt;

    for (;;)
    {
        c2_read(c2);

        log_debug("* Talking to %d from tab\n", c2->fd);
        tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_TAG, &tag);

        if (tag == TAB_TERM)
        {
            tlv_pkt_destroy(c2->tlv_pkt);
            break;
        }

        log_debug("* Tab forced to (tag: %d, fd: %d)\n", tag, c2->fd);

        if ((tlv_pkt = api_call_make(&c2->dynamic.api_calls, c2, tag)) == NULL)
            tlv_pkt = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);

        c2_write(c2, tlv_pkt);

        tlv_pkt_destroy(tlv_pkt);
        tlv_pkt_destroy(c2->tlv_pkt);
    }

    free(c2);
}
