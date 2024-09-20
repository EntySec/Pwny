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
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/types.h>

#include <tlv.h>
#include <c2.h>
#include <log.h>
#include <queue.h>

tlv_pkt_t *tlv_pkt_create(void)
{
    tlv_pkt_t *tlv_pkt;

    tlv_pkt = (tlv_pkt_t *)malloc(sizeof(tlv_pkt_t));

    if (tlv_pkt == NULL)
    {
        return NULL;
    }

    tlv_pkt->buffer = NULL;
    tlv_pkt->bytes = 0;
    tlv_pkt->count = 0;

    return tlv_pkt;
}

void tlv_pkt_destroy(tlv_pkt_t *tlv_pkt)
{
    if (tlv_pkt == NULL)
    {
        return;
    }

    if (tlv_pkt->buffer != NULL)
    {
        free(tlv_pkt->buffer);
    }

    free(tlv_pkt);
}

int tlv_pkt_add_raw(tlv_pkt_t *tlv_pkt, int type, void *value, size_t length)
{
    struct tlv_header header;

    tlv_pkt->buffer = realloc(tlv_pkt->buffer, tlv_pkt->bytes + TLV_HEADER + length);

    if (tlv_pkt->buffer == NULL)
    {
        return -1;
    }

    header.type = htonl(type);
    header.length = htonl(length);

    memcpy(tlv_pkt->buffer + tlv_pkt->bytes, &header.type, TLV_FIELD);
    memcpy(tlv_pkt->buffer + tlv_pkt->bytes + TLV_FIELD, &header.length, TLV_FIELD);
    memcpy(tlv_pkt->buffer + tlv_pkt->bytes + TLV_HEADER, value, length);

    tlv_pkt->bytes += TLV_HEADER + length;
    tlv_pkt->count++;
    return 0;
}

int tlv_pkt_add_u16(tlv_pkt_t *tlv_pkt, int type, int16_t value)
{
    value = htons(value);
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(value));
}

int tlv_pkt_add_u32(tlv_pkt_t *tlv_pkt, int type, int32_t value)
{
    value = htonl(value);
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(value));
}

int tlv_pkt_add_u64(tlv_pkt_t *tlv_pkt, int type, int64_t value)
{
    value = htonll(value);
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(value));
}

int tlv_pkt_add_string(tlv_pkt_t *tlv_pkt, int type, char *value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, value, strlen(value));
}

int tlv_pkt_add_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char *value, size_t length)
{
    return tlv_pkt_add_raw(tlv_pkt, type, value, length);
}

int tlv_pkt_add_tlv(tlv_pkt_t *tlv_pkt, int type, tlv_pkt_t *value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, value->buffer, value->bytes);
}

void *tlv_pkt_get_raw(tlv_pkt_t *tlv_pkt, int type, size_t *length)
{
    int offset;
    int count;

    struct tlv_header header;

    if (tlv_pkt->bytes < TLV_HEADER)
    {
        return NULL;
    }

    offset = 0;
    count = tlv_pkt->bytes - TLV_HEADER;

    while (offset < count)
    {
        memcpy(&header, tlv_pkt->buffer + offset, TLV_HEADER);
        offset += TLV_HEADER;

        if (ntohl(header.type) == type)
        {
            *length = ntohl(header.length);
            return tlv_pkt->buffer + offset;
        }

        offset += ntohl(header.length);
    }

    return NULL;
}

ssize_t tlv_pkt_get_u16(tlv_pkt_t *tlv_pkt, int type, int16_t *value)
{
    char *buffer;
    size_t length;

    buffer = tlv_pkt_get_raw(tlv_pkt, type, &length);
    if (!buffer || length != 2)
    {
        return -1;
    }

    memcpy(value, buffer, length);
    *value = ntohs(*value);
    return length;
}

ssize_t tlv_pkt_get_u32(tlv_pkt_t *tlv_pkt, int type, int32_t *value)
{
    char *buffer;
    size_t length;

    buffer = tlv_pkt_get_raw(tlv_pkt, type, &length);
    if (!buffer || length != 4)
    {
        return -1;
    }

    memcpy(value, buffer, length);
    *value = ntohl(*value);
    return length;
}

ssize_t tlv_pkt_get_u64(tlv_pkt_t *tlv_pkt, int type, int64_t *value)
{
    char *buffer;
    size_t length;

    buffer = tlv_pkt_get_raw(tlv_pkt, type, &length);
    if (!buffer || length != 8)
    {
        return -1;
    }

    memcpy(value, buffer, length);
    *value = ntohll(*value);
    return length;
}

ssize_t tlv_pkt_get_string(tlv_pkt_t *tlv_pkt, int type, char *value)
{
    size_t length;
    char *buffer;

    buffer = tlv_pkt_get_raw(tlv_pkt, type, &length);

    if (buffer == NULL)
    {
        return -1;
    }

    memcpy(value, buffer, length);
    value[length] = '\0';
    return length;
}

ssize_t tlv_pkt_get_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char **value)
{
    void *buffer;
    size_t length;

    buffer = tlv_pkt_get_raw(tlv_pkt, type, &length);
    if (!buffer)
    {
        return -1;
    }

    *value = malloc(length);
    if (*value == NULL)
    {
        return -1;
    }

    memcpy(*value, buffer, length);
    return length;
}

ssize_t tlv_pkt_get_tlv(tlv_pkt_t *tlv_pkt, int type, tlv_pkt_t **value)
{
    tlv_pkt_t *tlv;

    tlv = tlv_pkt_create();
    if (tlv == NULL)
    {
        return -1;
    }

    tlv->bytes = tlv_pkt_get_bytes(tlv_pkt, type, &tlv->buffer);

    *value = tlv;
    return tlv->bytes;
}