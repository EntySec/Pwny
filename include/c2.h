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
#include <stdlib.h>
#include <stdio.h>
#include <sigar.h>
#include <ev.h>

#include <link.h>
#include <tlv.h>
#include <net.h>

#include <uthash/uthash.h>

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#define PACK_IPV4(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

typedef void (*c2_read_t)(void *data);

typedef struct c2_table
{
    int id;
    char *uuid;

    struct
    {
        int t_count;
        int n_count;

        struct tabs_table *tabs;
        struct nodes_table *nodes;
        struct api_calls_table *api_calls;
        struct pipes_table *pipes;
    } dynamic;

    sigar_t *sigar;
    struct ev_loop *loop;
    net_t *net;

    tlv_pkt_t *request;
    tlv_pkt_t *response;

    void *link_data;
    link_t read_link;
    link_t write_link;

    UT_hash_handle hh;
} c2_t;

c2_t *c2_create(int id);

int c2_add_sock(c2_t **c2_table, int id, int sock);
int c2_add_file(c2_t **c2_table, int id, int fd);
int c2_add(c2_t **c2_table, c2_t *c2_new);

void c2_setup(c2_t *c2_table, struct ev_loop *loop);

void c2_set_links(c2_t *c2_table,
                  link_t read_link,
                  link_t write_link,
                  void *data);

int c2_process(c2_t *c2);

ssize_t c2_dequeue_tlv(c2_t *c2, tlv_pkt_t **tlv_pkt);
int c2_enqueue_tlv(c2_t *c2, tlv_pkt_t *tlv_pkt);

void c2_read(void *data);
void c2_write(void *data);

void c2_free(c2_t *c2_table);
void c2_destroy(c2_t *c2);

#endif
