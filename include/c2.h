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

#ifndef _C2_H_
#define _C2_H_

#include <pthread.h>
#include <stdint.h>

#include <tlv.h>

#include <uthash/uthash.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#define PACK_IPV4(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

typedef struct
{
    int id, fd;
    char *name;

    struct
    {
        int t_count, n_count;
        struct tabs_table *tabs;
        struct nodes_table *nodes;
        struct api_calls_table *api_calls;
    } dynamic;

    tlv_pkt_t *tlv_pkt;
    UT_hash_handle hh;
} c2_t;

c2_t *c2_create(int, int, char *);

int c2_write(c2_t *, tlv_pkt_t *);
int c2_read(c2_t *);

void c2_add(c2_t **, int, int, char *);
void c2_init(c2_t *);

#endif /* _C2_H_ */
