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

#include <stdlib.h>

#include <tlv.h>
#include <log.h>
#include <group.h>
#include <queue.h>
#include <tlv_types.h>

group_t *group_create(tlv_pkt_t *tlv_pkt)
{
    group_t *group;

    group = tlv_pkt_create();
    tlv_pkt_add_tlv(group, TLV_TYPE_GROUP, tlv_pkt);

    return group;
}

tlv_pkt_t *group_tlv(group_t *group)
{
    log_debug("* Getting global TLV_GROUP\n");
    return tlv_pkt_get_tlv(group, TLV_TYPE_GROUP);
}

int group_enqueue(queue_t *queue, group_t *group)
{
    if (tlv_pkt_serialize(group) != 0)
    {
        return -1;
    }

    if (queue_add_raw(queue, group->buffer, group->bytes) != 0)
    {
        return -1;
    }

    return 0;
}

int group_tlv_enqueue(queue_t *queue, tlv_pkt_t *tlv_pkt)
{
    group_t *group;

    group = group_create(tlv_pkt);

    if (group != NULL)
    {
        if (group_enqueue(queue, group) != 0)
        {
            group_destroy(group);
            return -1;
        }

        group_destroy(group);
        return 0;
    }

    return -1;
}

ssize_t group_tlv_dequeue(queue_t *queue, tlv_pkt_t **tlv_pkt)
{
    int total;
    group_t *group;

    if ((total = group_dequeue(queue, &group)) > 0)
    {
        *tlv_pkt = group_tlv(group);
        group_destroy(group);
    }

    return total;
}

ssize_t group_dequeue(queue_t *queue, group_t **group)
{
    int total;
    int length;

    struct tlv_header header;
    unsigned char *buffer;

    if (queue->bytes < sizeof(header))
    {
        return -1;
    }

    queue_copy(queue, &header, sizeof(header));
    length = header.length;

    if (queue->bytes < sizeof(header) + length)
    {
        return -1;
    }

    if ((buffer = malloc(length)) == NULL)
    {
        return -1;
    }

    total = queue_drain(queue, sizeof(header));
    queue_copy(queue, buffer, length);

    *group = tlv_pkt_create();

    if (tlv_pkt_add_raw(*group, header.type, buffer, length) < 0)
    {
        goto fail;
    }

    total += queue_drain(queue, length);
    return total;

fail:
    free(buffer);
    return -1;
}

void group_destroy(group_t *group)
{
    tlv_pkt_destroy(group);
}