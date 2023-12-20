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
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sigar.h>
#include <ev.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>

#include <log.h>
#include <tlv.h>
#include <api.h>
#include <c2.h>
#include <pipe.h>
#include <link.h>
#include <node.h>
#include <group.h>
#include <tlv_types.h>
#include <machine.h>

#include <uthash/uthash.h>

c2_t *c2_create(int id)
{
    c2_t *c2;
    char uuid[UUID_SIZE];

    c2 = calloc(1, sizeof(*c2));

    if (c2 == NULL)
    {
        return NULL;
    }

    c2->id = id;
    machine_uuid(uuid);
    c2->uuid = uuid;

    c2->dynamic.t_count = 0;
    c2->dynamic.n_count = 0;
    c2->dynamic.tabs = NULL;
    c2->dynamic.nodes = NULL;
    c2->dynamic.api_calls = NULL;

    return c2;
}

int c2_add_sock(c2_t **c2_table, int id, int sock)
{
    c2_t *c2;

    c2 = c2_create(id);

    if (c2 != NULL)
    {
        c2->net = net_create(sock, NET_PROTO_TCP);

        if (c2->net == NULL)
        {
            goto fail;
        }

        if (net_block_sock(c2->net->sock) < 0)
        {
            goto fail;
        }

        return c2_add(c2_table, c2);
    }

    return -1;

fail:
    c2_destroy(c2);
    return -1;
}

int c2_add_file(c2_t **c2_table, int id, int fd)
{
    c2_t *c2;

    c2 = c2_create(id);

    if (c2 != NULL)
    {
        c2->net = net_create(fd, NET_PROTO_FILE);

        if (c2->net == NULL)
        {
            c2_destroy(c2);
            return -1;
        }

        return c2_add(c2_table, c2);
    }

    return -1;
}

int c2_add(c2_t **c2_table, c2_t *c2_new)
{
    int id;
    c2_t *c2;

    id = c2_new->id;
    HASH_FIND_INT(*c2_table, &id, c2);

    if (c2 == NULL)
    {
        HASH_ADD_INT(*c2_table, id, c2_new);
        log_debug("* Added C2 entry (%d) - (%s)\n", id, c2_new->uuid);

        return 0;
    }

    return -1;
}

void c2_destroy(c2_t *c2)
{
    tabs_free(c2->dynamic.tabs);
    nodes_free(c2->dynamic.nodes);

    if (c2->uuid != NULL)
    {
        free(c2->uuid);
    }

    net_free(c2->net);
    sigar_close(c2->sigar);
    api_calls_free(c2->dynamic.api_calls);
    pipes_free(c2->dynamic.pipes);

    free(c2);
}

void c2_set_links(c2_t *c2_table,
                  link_t read_link,
                  link_t write_link,
                  void *data)
{
    c2_t *c2;

    for (c2 = c2_table; c2 != NULL; c2 = c2->hh.next)
    {
        c2->read_link = read_link;
        c2->write_link = write_link;
        c2->link_data = data != NULL ? data : c2;
    }
}

ssize_t c2_dequeue_tlv(c2_t *c2, tlv_pkt_t **tlv_pkt)
{
    return group_tlv_dequeue(c2->net->ingress, tlv_pkt);
}

int c2_enqueue_tlv(c2_t *c2, tlv_pkt_t *tlv_pkt)
{
    if (group_tlv_enqueue(c2->net->egress, tlv_pkt) >= 0)
    {
        if (c2->write_link)
        {
            c2->write_link(c2->link_data);
        }

        return 0;
    }

    return -1;
}

void c2_setup(c2_t *c2_table, struct ev_loop *loop)
{
    c2_t *c2;

    for (c2 = c2_table; c2 != NULL; c2 = c2->hh.next)
    {
        log_debug("* Initializing C2 server (%d) - (%s)\n",
                  c2->id, c2->uuid);

        c2->loop = loop;
        sigar_open(&c2->sigar);

        net_set_links(c2->net, c2->read_link, c2->write_link, c2->link_data);
        net_setup(c2->net, c2->loop);

        register_pipe_api_calls(&c2->dynamic.api_calls);
        api_calls_register(&c2->dynamic.api_calls);
        pipes_register(&c2->dynamic.pipes);
    }
}

void c2_free(c2_t *c2_table)
{
    c2_t *c2;

    for (c2 = c2_table; c2 != NULL; c2 = c2->hh.next)
    {
        log_debug("* Freeing C2 server (%d) - (%s)\n",
                  c2->id, c2->uuid);

        HASH_DEL(c2_table, c2);
        c2_destroy(c2);
    }

    free(c2_table);
}
