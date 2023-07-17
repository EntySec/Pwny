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

#include <pthread.h>
#include <stdint.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include <uthash/uthash.h>

/* Macro definitions */

#define MAX_HOSTNAME_BUF 1024
#define NET_NODE_CHUNK 4096

#define PACK_IPV4(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

/* Essential data types definitions */

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

typedef struct net_c2 {
    int net_c2_id;
    int net_c2_fd;
    char *net_c2_name;
    UT_hash_handle hh;
} net_c2_t;

typedef struct net_nodes {
    int net_node_id;
    pthread_t net_node_handle;
    UT_hash_handle hh;
} net_nodes_t;

typedef struct net_node {
    ipv4_t net_node_src_host;
    port_t net_node_src_port;
    ipv4_t net_node_dst_host;
    port_t net_node_dst_port;
} net_node_t;

/* Grabbing essential network information */

char *net_local_hostname();

/* Network nodes addition and deletion */

void net_nodes_add(net_nodes_t **, int, net_node_t);
void net_nodes_delete(net_nodes_t **, int);

/* Network C2 addition and initialization */

void net_c2_add(net_c2_t **, int, int, char *);
void net_c2_init(net_c2_t *);

/* Network nodes clean up */

void net_nodes_free(net_nodes_t *);

#endif /* _NET_H_ */
