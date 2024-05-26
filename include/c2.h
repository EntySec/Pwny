/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
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

/*! \file c2.h
 *  \brief Manage C2 (Command & Control) servers
 */

#ifndef _C2_H_
#define _C2_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sigar.h>
#include <ev.h>

#include <link.h>
#include <tunnel.h>
#include <group.h>
#include <crypt.h>
#include <tlv.h>

#include <uthash/uthash.h>

#ifndef IS_WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

struct c2_table
{
    int id;

    struct ev_loop *loop;
    tunnel_t *tunnel;

    struct pipes_table *pipes;
    crypt_t *crypt;

    tlv_pkt_t *request;
    tlv_pkt_t *response;

    void *data;
    void *link_data;
    link_t read_link;
    link_t write_link;
    link_event_t event_link;

    UT_hash_handle hh;
};

typedef struct c2_table c2_t;

c2_t *c2_create(int id);
c2_t *c2_add_uri(c2_t **c2_table, int id, char *uri, tunnels_t *tunnels);

void c2_setup(c2_t *c2, struct ev_loop *loop, struct pipes_table *pipes, void *data);
void c2_start(c2_t *c2);
void c2_stop(c2_t *c2);

void c2_set_links(c2_t *c2,
                  link_t read_link,
                  link_t write_link,
                  link_event_t event_link,
                  void *data);

ssize_t c2_dequeue_tlv(c2_t *c2, tlv_pkt_t **tlv_pkt);
int c2_enqueue_tlv(c2_t *c2, tlv_pkt_t *tlv_pkt);

int c2_active_tunnels(c2_t *c2_table);

void c2_read(void *data);
void c2_write(void *data);

void c2_free(c2_t *c2_table);

#endif
