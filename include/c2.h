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
#include <tlv.h>
#include <net.h>

#include <uthash/uthash.h>

#ifndef IS_WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#define C2_CORE 1
#define C2_TAB 2

#define PACK_IPV4(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

typedef void (*c2_read_t)(void *data);

/*! \struct c2_table
 *  \brief C2 (command & control) instance structure
 */

struct c2_table
{
    int id;
    int type;
    char *uuid;
    const char *path;

    struct
    {
        int t_count;
        int n_count;

        struct tabs_table *tabs;
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
};

typedef struct c2_table c2_t;

/*! \fn c2_t *c2_create(int id)
 *  \brief create C2 instance
 *
 *  \param id ID to create instance with
 *  \return C2 instance
 */

c2_t *c2_create(int id);

/*! \fn int c2_add_sock(c2_t **c2_table, int id, int sock, int proto)
 *  \brief add socket to C2 instance
 *
 *  \param c2_table C2 table to search instance in
 *  \param id ID of an instance to add sock to
 *  \param sock socket file descriptor to read/write
 *  \param proto protocol to use for C2
 *  \return error code
 */

int c2_add_sock(c2_t **c2_table, int id, int sock, int proto);

/*! \fn int c2_add_file(c2_t **c2_table, int id, int in, int out)
 *  \brief add file descriptor to C2 instance
 *
 *  \param c2_table C2 table to search instance in
 *  \param id ID of an instance to add sock to
 *  \param in file descriptor to read from
 *  \param out file descriptor to write to
 *  \return error code
 */

int c2_add_file(c2_t **c2_table, int id, int in, int out);

/*! \fn int c2_add(c2_t **c2_table, c2_t *c2_new)
 *  \brief add C2 instance to hash table
 *
 *  \param c2_table hash table of C2 instances
 *  \param c2_new C2 instance to add to C2 table
 *  \return error code
 */

int c2_add(c2_t **c2_table, c2_t *c2_new);

/*! \fn void c2_setup(c2_t *c2_table, struct ev_loop *loop)
 *  \brief link each C2 instance from the table to a specific event loop
 *
 *  \param c2_table hash table containing C2 instances
 *  \param loop event loop to link
 */

void c2_setup(c2_t *c2_table, struct ev_loop *loop);

/*! \fn void c2_set_links(c2_t *c2_table
 *                        link_t read_link,
 *                        link_t write_link,
 *                        void *data)
 *  \brief set links for add C2 instances in table
 *
 *  \param c2_table hash table containing C2 instances
 *  \param read_link link to be called on read event
 *  \param write_link link to be called on write event
 *  \param data argument to pass to a link
 */

void c2_set_links(c2_t *c2_table,
                  link_t read_link,
                  link_t write_link,
                  void *data);

/*! \fn ssize_t c2_dequeue_tlv(c2_t *c2, tlv_pkt_t **tlv_pkt)
 *  \brief retrieve TLV packet from specific C2's queue
 *
 *  \param c2 specific C2 to dequeue TLV packet from
 *  \param tlv_pkt TLV packet to dequeue to
 *  \return size of dequeued TLV packet including header
 */

ssize_t c2_dequeue_tlv(c2_t *c2, tlv_pkt_t **tlv_pkt);

/*! \fn ssize_t c2_enqueue_tlv(c2_t *c2, tlv_pkt_t *tlv_pkt)
 *  \brief add TLV packet to a specific C2's queue
 *
 *  \param c2 specific C2 to enqueue TLV packet to
 *  \param tlv_pkt TLV packet to enqueue
 *  \return error code
 */

int c2_enqueue_tlv(c2_t *c2, tlv_pkt_t *tlv_pkt);

/*! \fn void c2_enqueue_uuid(c2_t *c2_table)
 *  \brief iterate C2 table and enqueue UUID of each C2 to this C2's queue
 *
 *  \note this is the first step of negotiating with the C2 server
 *        UUID identifies the client and used to check if negotiation is eastablished
 *
 *  \param c2_table hash table containing C2 instances
*/

void c2_enqueue_uuid(c2_t *c2_table);

void c2_read(void *data);
void c2_write(void *data);

/*! \fn void c2_free(c2_t *c2_table)
 *  \brief free hash table containing C2 instances
 *
 *  \param c2_table C2 table to free
 */

void c2_free(c2_t *c2_table);

/*! \fn void c2_destroy(c2_t *c2)
 *  \brief destroy a single C2 instance freeing it
 *
 *  \param c2 C2 instance to destroy
 */

void c2_destroy(c2_t *c2);

#endif
