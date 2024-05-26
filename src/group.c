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

#include <stdlib.h>

#include <tlv.h>
#include <log.h>
#include <group.h>
#include <queue.h>
#include <crypt.h>
#include <tlv_types.h>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>

#include <arpa/inet.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

group_t *group_create(tlv_pkt_t *tlv_pkt, crypt_t *crypt)
{
    group_t *group;
    unsigned char *buffer;
    ssize_t bytes;

    bytes = crypt_process(crypt, tlv_pkt->buffer, tlv_pkt->bytes,
                          &buffer, CRYPT_ENCRYPT);

    if (bytes < 0)
    {
        log_debug("* Failed to enqueue TLV packet\n");
        return NULL;
    }

    group = tlv_pkt_create();
    tlv_pkt_add_bytes(group, TLV_TYPE_GROUP, buffer, bytes);
    free(buffer);

    return group;
}

int group_tlv_enqueue(queue_t *queue, tlv_pkt_t *tlv_pkt, crypt_t *crypt)
{
    group_t *group;

    group = group_create(tlv_pkt, crypt);

    if (group == NULL)
    {
        log_debug("* Failed to encapsulate TLV packet\n");
        return -1;
    }

    if (queue_add_raw(queue, group->buffer, group->bytes) != 0)
    {
        log_debug("* Failed to add TLV packet to queue\n");
        group_destroy(group);
        return -1;
    }

    group_destroy(group);
    return 0;
}

ssize_t group_tlv_dequeue(queue_t *queue, tlv_pkt_t **tlv_pkt, crypt_t *crypt)
{
    ssize_t total;
    size_t length;

    tlv_pkt_t *tlv;
    struct tlv_header header;
    unsigned char *buffer;

    if (queue->bytes < TLV_HEADER)
    {
        return -1;
    }

    queue_copy(queue, &header, TLV_HEADER);
    length = ntohl(header.length);

    if (queue->bytes < TLV_HEADER + length)
    {
        log_debug("* Failed to read TLV packet (corruption?)\n");
        return -1;
    }

    if (ntohl(header.type) != TLV_TYPE_GROUP)
    {
        log_debug("* No TLV_GROUP received, dropping packet\n");
        return -1;
    }

    if ((buffer = malloc(length)) == NULL)
    {
        log_debug("* Failed to allocate memory for packet\n");
        return -1;
    }

    total = queue_drain(queue, TLV_HEADER);
    queue_copy(queue, buffer, length);

    tlv = tlv_pkt_create();
    tlv->bytes = crypt_process(crypt, buffer, length,
                               &tlv->buffer, CRYPT_DECRYPT);

    if (tlv->bytes < 0)
    {
        log_debug("* Failed to dequeue TLV packet\n");
        goto fail;
    }

    *tlv_pkt = tlv;
    total += queue_drain(queue, length);
    free(buffer);

    return total;

fail:
    tlv_pkt_destroy(tlv);
    free(buffer);
    return -1;
}

void group_destroy(group_t *group)
{
    tlv_pkt_destroy(group);
}
