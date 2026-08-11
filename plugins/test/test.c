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


#include <pwny/tlv.h>
#include <pwny/tlv_types.h>
#include <pwny/tab_lite.h>

#define TEST \
        TLV_TAG_CUSTOM(API_CALL_DYNAMIC, \
                       TAB_BASE, \
                       API_CALL)

static tlv_pkt_t *test(tab_lite_c2_t *c2)
{
    tlv_pkt_t *result;

    result = tab_lite_craft_response(TAB_STATUS_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_STRING, "Test");

    return result;
}

int main(void)
{
    tab_lite_t *tab;

    tab = tab_lite_create();
    tab_lite_setup(tab);

    tab_lite_register_call(tab, TEST, test);

    tab_lite_start(tab);
    tab_lite_destroy(tab);

    return 0;
}