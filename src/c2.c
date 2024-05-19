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
#include <tab.h>
#include <api.h>
#include <c2.h>
#include <pipe.h>
#include <link.h>
#include <group.h>
#include <tlv_types.h>

#include <uthash/uthash.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

c2_t *c2_create(int id)
{
    c2_t *c2;

    c2 = calloc(1, sizeof(*c2));

    if (c2 == NULL)
    {
        return NULL;
    }

    c2->id = id;
    c2->pipes = NULL;
    c2->crypt = crypt_create();

    return c2;
}

c2_t *c2_add_uri(c2_t **c2_table, int id, char *uri, tunnels_t *tunnels)
{
    c2_t *c2;
    c2_t *c2_temp;
    tunnels_t *tunnel;

    c2 = c2_create(id);

    if (c2 == NULL)
    {
        return NULL;
    }

    tunnel = tunnel_find(tunnels, uri);
    if (tunnel == NULL)
    {
        log_debug("* Failed to find protocol for (%s)\n", uri);
        goto fail;
    }

    c2->tunnel = tunnel_create(tunnel);
    if (c2->tunnel == NULL)
    {
        log_debug("* Failed to create tunnel for C2 (%d)\n", c2->id);
        goto fail;
    }

    tunnel_set_uri(c2->tunnel, uri);
    HASH_FIND_INT(*c2_table, &id, c2_temp);

    if (c2_temp != NULL)
    {
        log_debug("* Failed to add C2 to C2 table (%d)\n", c2->id);
        goto fail;
    }

    HASH_ADD_INT(*c2_table, id, c2);
    log_debug("* Added C2 entry (%d)\n", id);

    return c2;

fail:
    free(c2);
    return NULL;
}

void c2_set_links(c2_t *c2,
                  link_t read_link,
                  link_t write_link,
                  link_event_t event_link,
                  void *data)
{
    c2->read_link = read_link;
    c2->write_link = write_link;
    c2->event_link = event_link;
    c2->link_data = data != NULL ? data : c2;
}

ssize_t c2_dequeue_tlv(c2_t *c2, tlv_pkt_t **tlv_pkt)
{
    return group_tlv_dequeue(c2->tunnel->ingress, tlv_pkt, c2->crypt);
}

int c2_enqueue_tlv(c2_t *c2, tlv_pkt_t *tlv_pkt)
{
    if (group_tlv_enqueue(c2->tunnel->egress, tlv_pkt, c2->crypt) < 0)
    {
        return -1;
    }

    if (c2->write_link)
    {
        c2->write_link(c2->link_data);
    }

    return 0;
}

void c2_setup(c2_t *c2, struct ev_loop *loop, struct pipes_table *pipes, void *data)
{
    c2->loop = loop;

    tunnel_setup(c2->tunnel, c2->loop);
    tunnel_set_links(c2->tunnel, c2->read_link,
                     c2->write_link, c2->event_link,
                     c2->link_data);

    c2->pipes = pipes;
    c2->data = data;
}

void c2_start(c2_t *c2)
{
    log_debug("* Starting C2 server (%d)\n",
              c2->id);

    if (tunnel_init(c2->tunnel) < 0)
    {
        log_debug("* Failed to initialize tunnel for C2 (%d)\n", c2->id);
    }

    tunnel_start(c2->tunnel);
}

void c2_stop(c2_t *c2)
{
    log_debug("* Stopping C2 server (%d)\n",
              c2->id);

    tunnel_exit(c2->tunnel);
    crypt_set_secure(c2->crypt, STAT_NOT_SECURE);
}

int c2_active_tunnels(c2_t *c2_table)
{
    c2_t *c2;
    c2_t *c2_tmp;
    int count;

    count = 0;

    HASH_ITER(hh, c2_table, c2, c2_tmp)
    {
        if (c2->tunnel->active)
        {
            count++;
        }
    }

    return count;
}

void c2_free(c2_t *c2_table)
{
    c2_t *c2;
    c2_t *c2_tmp;

    HASH_ITER(hh, c2_table, c2, c2_tmp)
    {
        log_debug("* Freeing C2 server (%d)\n",
                  c2->id);

        HASH_DEL(c2_table, c2);

        c2_stop(c2);
        api_pipes_free(c2->pipes);
        tunnel_free(c2->tunnel);
        crypt_free(c2->crypt);
        free(c2);
    }

    free(c2_table);
}
