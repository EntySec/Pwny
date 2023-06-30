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

#ifndef _NET_H_
#define _NET_H_

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include <uthash/uthash.h>

#define MAX_HOSTNAME_BUF 1024

#define PACK_IPV4(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

typedef struct net_c2 {
    int net_c2_id;
    int net_c2_fd;
    char *net_c2_name;
    UT_hash_handle hh;
} net_c2_t;

typedef struct net_data {
    #ifndef WINDOWS
    int net_data_src;
    int net_data_dst;
    #else
    SOCKET net_data_src;
    SOCKET net_data_dst;
    #endif
} net_data_t;

typedef struct net_forwarder {
    #ifndef WINDOWS
    int net_forwarder_pipe;
    #else
    SOCKET net_forwarder_pipe;
    #endif

    int net_forward_port;
    int net_mother_port;
    char *net_mother_host;
} net_forwarder_t;

char *net_local_hostname();

int net_traffic_forward(net_forwarder_t *);

void net_c2_add(net_c2_t **, int, int, char *);
void net_c2_init(net_c2_t *);
void net_c2_free(net_c2_t *);

#endif /* _NET_H_ */
