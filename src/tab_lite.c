/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

/*
 * Lightweight tab runtime for Pwny plugins.
 *
 * This replaces the heavy tab.c which pulls in the full C2 stack
 * (c2.c -> tunnel.c -> net_client.c -> io.c -> crypt.c -> group.c)
 * and transitively all of: mbedtls, curl, sigar, eio, zlib.
 *
 * A tab communicates over inherited stdin/stdout pipes using the
 * TLV group framing protocol with no encryption (the parent handles
 * encryption on the C2 transport layer). This file provides a fully
 * self-contained implementation needing only: tlv.c, queue.c, log.c,
 * and libev — dropping from ~1 MB+ down to ~30-40 KB.
 *
 * The API dispatch (register, lookup, craft response) is inlined
 * here to avoid pulling in api.c which transitively requires
 * tabs.c -> child.c -> the entire process subsystem.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ev.h>

#include <arpa/inet.h>

#include <pwny/log.h>
#include <pwny/tlv.h>
#include <pwny/tlv_types.h>
#include <pwny/queue.h>

#include <pwny/tab_lite.h>

#include <uthash/uthash.h>

/* ============================================================
 * Embedded API dispatch (avoids linking api.c)
 * ============================================================ */

static void tab_api_register(tab_api_entry_t **api_calls,
                             int tag, tab_api_t handler)
{
    tab_api_entry_t *entry;
    tab_api_entry_t *new_entry;

    HASH_FIND_INT(*api_calls, &tag, entry);
    if (entry != NULL)
    {
        return;
    }

    new_entry = calloc(1, sizeof(*new_entry));
    if (new_entry == NULL)
    {
        return;
    }

    new_entry->tag = tag;
    new_entry->handler = handler;
    HASH_ADD_INT(*api_calls, tag, new_entry);
}

static int tab_api_call(tab_api_entry_t **api_calls,
                        tab_lite_c2_t *c2, int tag,
                        tlv_pkt_t **result)
{
    tab_api_entry_t *entry;

    HASH_FIND_INT(*api_calls, &tag, entry);
    if (entry != NULL)
    {
        *result = entry->handler(c2);
        return 0;
    }

    *result = NULL;
    return -1;
}

static void tab_api_free(tab_api_entry_t *api_calls)
{
    tab_api_entry_t *entry;
    tab_api_entry_t *tmp;

    HASH_ITER(hh, api_calls, entry, tmp)
    {
        HASH_DEL(api_calls, entry);
        free(entry);
    }
}

tlv_pkt_t *tab_lite_craft_response(int status, tlv_pkt_t *request)
{
    int tag;
    int tab_id;
    tlv_pkt_t *pkt;

    pkt = tlv_pkt_create();
    tlv_pkt_add_u32(pkt, TLV_TYPE_STATUS, status);

    if (request != NULL &&
        tlv_pkt_get_u32(request, TLV_TYPE_TAG, &tag) >= 0)
    {
        tlv_pkt_add_u32(pkt, TLV_TYPE_TAG, tag);
    }

    if (request != NULL &&
        tlv_pkt_get_u32(request, TLV_TYPE_TAB_ID, &tab_id) >= 0)
    {
        tlv_pkt_add_u32(pkt, TLV_TYPE_TAB_ID, tab_id);
    }

    return pkt;
}

/* ============================================================
 * Lightweight group framing (no encryption, no mbedtls)
 *
 * Wire format: each message is a TLV_TYPE_GROUP envelope
 * containing the raw serialized inner TLV as its value.
 * ============================================================ */

static int tab_group_enqueue(queue_t *queue, tlv_pkt_t *tlv_pkt)
{
    tlv_pkt_t *group;
    int ret;

    group = tlv_pkt_create();
    if (group == NULL)
    {
        return -1;
    }

    tlv_pkt_add_bytes(group, TLV_TYPE_GROUP,
                      tlv_pkt->buffer, tlv_pkt->bytes);

    ret = queue_add_raw(queue, group->buffer, group->bytes);
    tlv_pkt_destroy(group);

    return ret;
}

static ssize_t tab_group_dequeue(queue_t *queue, tlv_pkt_t **tlv_pkt)
{
    ssize_t total;
    size_t length;
    struct tlv_header header;
    tlv_pkt_t *tlv;

    if (queue->bytes < TLV_HEADER)
    {
        return -1;
    }

    queue_copy(queue, &header, TLV_HEADER);
    length = ntohl(header.length);

    if (queue->bytes < TLV_HEADER + length)
    {
        return -1;
    }

    if (ntohl(header.type) != TLV_TYPE_GROUP)
    {
        log_debug("* tab_lite: no TLV_GROUP, dropping\n");
        queue_drain(queue, TLV_HEADER + length);
        return -1;
    }

    tlv = tlv_pkt_create();
    if (tlv == NULL)
    {
        return -1;
    }

    total = queue_drain(queue, TLV_HEADER);

    tlv->buffer = malloc(length);
    if (tlv->buffer == NULL)
    {
        tlv_pkt_destroy(tlv);
        return -1;
    }

    queue_copy(queue, tlv->buffer, length);
    tlv->bytes = (ssize_t)length;
    total += queue_drain(queue, length);

    *tlv_pkt = tlv;
    return total;
}

/* ============================================================
 * Flush egress queue to stdout
 * ============================================================ */

static void tab_flush(tab_lite_t *tab)
{
    void *buffer;
    ssize_t size;

    while ((size = queue_remove_all(tab->egress, &buffer)) > 0)
    {
        write(STDOUT_FILENO, buffer, size);
        free(buffer);
    }
}

/* ============================================================
 * Event loop callbacks
 * ============================================================ */

static void tab_signal_handler(struct ev_loop *loop,
                               ev_signal *w, int revents)
{
    (void)revents;

    switch (w->signum)
    {
        case SIGINT:
        case SIGTERM:
            ev_break(loop, EVBREAK_ALL);
            break;
        default:
            break;
    }
}

static void tab_stdin_cb(struct ev_loop *loop,
                         struct ev_io *w, int revents)
{
    tab_lite_t *tab;
    tab_lite_c2_t fake_c2;
    tlv_pkt_t *request;
    tlv_pkt_t *result;

    int tag;
    int status;

    (void)revents;

    tab = (tab_lite_t *)w->data;

    if (queue_from_fd(tab->ingress, STDIN_FILENO) <= 0)
    {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    while (tab_group_dequeue(tab->ingress, &request) > 0)
    {
        tag = 0;
        result = NULL;
        status = -1;

        if (tlv_pkt_get_u32(request, TLV_TYPE_TAG, &tag) < 0)
        {
            result = tab_lite_craft_response(TAB_STATUS_NOT_IMPLEMENTED,
                                             request);
            goto send;
        }

        log_debug("* tab_lite: dispatching tag=%d\n", tag);

        memset(&fake_c2, 0, sizeof(fake_c2));
        fake_c2.request = request;

        if (tab_api_call(&tab->api_calls, &fake_c2, tag,
                         &result) != 0)
        {
            result = tab_lite_craft_response(TAB_STATUS_NOT_IMPLEMENTED,
                                             request);
            goto send;
        }

        if (result == NULL)
        {
            tlv_pkt_destroy(request);
            continue;
        }

send:
        if (result != NULL)
        {
            tlv_pkt_get_u32(result, TLV_TYPE_STATUS, &status);
            tab_group_enqueue(tab->egress, result);
            tab_flush(tab);
            tlv_pkt_destroy(result);
        }

        tlv_pkt_destroy(request);

        if (status == TAB_STATUS_QUIT)
        {
            ev_break(loop, EVBREAK_ALL);
            return;
        }
    }
}

/* ============================================================
 * Tab termination handler
 * ============================================================ */

static tlv_pkt_t *tab_term_handler(tab_lite_c2_t *c2)
{
    return tab_lite_craft_response(TAB_STATUS_QUIT, c2->request);
}

/* ============================================================
 * Public API
 * ============================================================ */

tab_lite_t *tab_lite_create(void)
{
    tab_lite_t *tab;

    tab = calloc(1, sizeof(*tab));
    if (tab == NULL)
    {
        return NULL;
    }

    tab->loop = ev_default_loop(TAB_LITE_EV_FLAGS);
    tab->api_calls = NULL;
    tab->ingress = queue_create();
    tab->egress = queue_create();

    {
        int flags;
        flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
        flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
        fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
    }

    return tab;
}

void tab_lite_setup(tab_lite_t *tab)
{
    tab_api_register(&tab->api_calls, TAB_LITE_TERM, tab_term_handler);
}

void tab_lite_register_call(tab_lite_t *tab, int tag,
                            tab_api_t handler)
{
    tab_api_register(&tab->api_calls, tag, handler);
}

int tab_lite_start(tab_lite_t *tab)
{
    ev_signal sigint_w, sigterm_w;
    ev_io stdin_io;

    ev_signal_init(&sigint_w, tab_signal_handler, SIGINT);
    ev_signal_start(tab->loop, &sigint_w);
    ev_signal_init(&sigterm_w, tab_signal_handler, SIGTERM);
    ev_signal_start(tab->loop, &sigterm_w);

    ev_io_init(&stdin_io, tab_stdin_cb, STDIN_FILENO, EV_READ);
    stdin_io.data = tab;
    ev_io_start(tab->loop, &stdin_io);

    return ev_run(tab->loop, 0);
}

void tab_lite_destroy(tab_lite_t *tab)
{
    ev_break(tab->loop, EVBREAK_ALL);

    if (tab->ingress)
    {
        queue_free(tab->ingress);
    }

    if (tab->egress)
    {
        queue_free(tab->egress);
    }

    tab_api_free(tab->api_calls);
    free(tab);
}
