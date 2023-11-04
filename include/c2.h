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
#include <stdio.h>
#include <sigar.h>

#include <tlv.h>

#include <uthash/uthash.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#define PACK_IPV4(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

#define NULL_FD -1

#define FD_CLOSE 0
#define FD_LEAVE 1

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

    sigar_t *sigar;

    tlv_pkt_t *tlv_pkt;
    UT_hash_handle hh;
} c2_t;

c2_t *c2_create(int id, int fd, char *name);

int c2_write_status(c2_t *c2, int status);
int c2_read_status(c2_t *c2, int *status);

int c2_write(c2_t *c2, tlv_pkt_t *tlv_pkt);
int c2_read(c2_t *c2, tlv_pkt_t **tlv_pkt);

int c2_write_file(c2_t *c2, FILE *file);
int c2_read_file(c2_t *c2, FILE *file);

void c2_add(c2_t **c2_table, int id, int fd, char *name);
void c2_init(c2_t *c2_table);

void c2_destroy(c2_t *c2, int flags);

#endif
