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
#include <c2.h>
#include <tlv.h>
#include <console.h>

#define TEST_POOL 2

c2_api_call_t *test_test(tlv_pkt_t tlv_packet)
{
    return craft_c2_api_call_pkt(tlv_packet, API_CALL_SUCCESS, "Test");
}

int main(void)
{
    c2_api_calls_t *c2_api_calls_table = NULL;

    c2_register_api_call(&c2_api_calls_table, TAB_API_CALL, test_test, TEST_POOL);

    tab_console_loop(c2_api_calls_table);
    c2_api_calls_free(c2_api_calls_table);

    return 0;
}