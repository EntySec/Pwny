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

#ifndef _NODE_H_
#define _NODE_H_

#include <uthash/uthash.h>

/* Essential data types definitions */

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

typedef struct {
    int id;
    ipv4_t src_host, src_port;
    port_t src_port, dst_port;
    pthread_t handle;
    UT_hash_handle hh;
} nodes_t;

/* Network nodes addition and deletion */

void node_add(nodes_t **, int, ipv4_t, port_t, ipv4_t, port_t);
void node_delete(nodes_t **, int);

/* Network nodes clean up */

void nodes_free(nodes_t *);

#endif /* _NODE_H_ */