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

#include <tab.h>
#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>
#include <console.h>

#define TEST TLV_TYPE_TAG | 5001

static tlv_pkt_t *test_test(c2_t *c2)
{
    tlv_pkt_t *result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    tlv_pkt_add_string(result, TLV_TYPE_STRING, "Test");
    return result;
}

int main(void)
{
    c2_t *c2 = c2_create(0, STDIN_FILENO, "test");

    api_call_register(&c2->dynamic.api_calls, TEST | 1, test_test);

    tab_console_loop(c2);

    return 0;
}