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

#include <stdio.h>
#include <stdlib.h>

#include <net.h>
#include <tlv.h>

int main(int argc, char *argv[])
{
	net_c2_t *net_c2_data = NULL;

	tlv_transport_channel_t tlv_transport_channel_new = {
		.tlv_transport_channel_host = PACK_IPV4(127, 0, 0, 1),
		.tlv_transport_channel_port = 8888,
	};

	tlv_transport_channel_open(&tlv_transport_channel_new);

	net_c2_add(&net_c2_data, 0, tlv_transport_channel_new.tlv_transport_channel_pipe, net_local_hostname());
	net_c2_init(net_c2_data);

	tlv_transport_channel_close(&tlv_transport_channel_new);
	return 0;
}
