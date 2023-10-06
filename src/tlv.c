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
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>

#include <tlv.h>
#include <c2.h>
#include <log.h>
#include <key_list.h>

static void tlv_pkt_release(value_t value)
{
    tlv_t *tlv;

    tlv = (tlv_t *)value.value;

    free(tlv->value);
    free(tlv);
}

tlv_pkt_t *tlv_pkt_create(void)
{
    tlv_pkt_t *tlv_pkt;

    tlv_pkt = (tlv_pkt_t *)malloc(sizeof(tlv_pkt_t));

    if (tlv_pkt != NULL)
    {
        tlv_pkt->list = key_list_create(tlv_pkt_release);
        tlv_pkt->buffer = NULL;
        tlv_pkt->bytes = 0;
        tlv_pkt->count = 0;

        return tlv_pkt;
    }

    return NULL;
}

int tlv_pkt_write(int fd, tlv_pkt_t *tlv_pkt)
{
    if (tlv_pkt_serialize(tlv_pkt) != 0)
        return -1;

    write(fd, tlv_pkt->buffer, tlv_pkt->bytes);
    return 0;
}

int tlv_pkt_read(int fd, tlv_pkt_t *tlv_pkt)
{
    int tlv_type;
    int tlv_length;

    unsigned char type[sizeof(int)];
    unsigned char length[sizeof(int)];
    unsigned char *buffer;

    read(fd, type, sizeof(int));
    tlv_type = (*(int *)type);

    read(fd, length, sizeof(int));
    tlv_length = (*(int *)length);

    buffer = malloc(tlv_length);
    if (buffer == NULL)
        return -1;

    read(fd, buffer, tlv_length);

    if (tlv_pkt_add_raw(tlv_pkt, tlv_type, buffer, tlv_length) < 0)
    {
        free(buffer);
        return -1;
    }

    free(buffer);
    return 0;
}

tlv_pkt_t *tlv_pkt_parse(unsigned char *buffer, int size)
{
    int type;
    int length;
    int count;
    int offset;

    unsigned char *cache;

    tlv_pkt_t *tlv_pkt;

    tlv_pkt = tlv_pkt_create();

    if (tlv_pkt == NULL)
        return NULL;

    cache = (unsigned char *)malloc(size);
    memcpy(cache, buffer, size);

    offset = 0;
    count = 0;

    while (offset < size)
    {
        type = (*(int *)(cache + offset));
        offset += sizeof(int);
        length = (*(int *)(cache + offset));
        offset += sizeof(int);
        tlv_pkt_add_raw(tlv_pkt, type, cache+offset, length);
        offset += length;

        count++;
    }

    tlv_pkt->buffer = cache;
    tlv_pkt->bytes = size;
    tlv_pkt->count = count;

    return tlv_pkt;
}

int tlv_pkt_delete(tlv_pkt_t *tlv_pkt, int type)
{
    return key_list_delete(tlv_pkt->list, type);
}

void tlv_pkt_destroy(tlv_pkt_t *tlv_pkt)
{
    key_list_destroy(tlv_pkt->list);

    if (tlv_pkt->buffer != NULL)
        free(tlv_pkt->buffer);

    free(tlv_pkt);
}

int tlv_pkt_add_raw(tlv_pkt_t *tlv_pkt, int type, void *value, int length)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (tlv_pkt->buffer != NULL)
        return -1;

    tlv = (tlv_t *)malloc(sizeof(tlv_t));

    tlv->type = type;
    tlv->length = length;
    tlv->value = (unsigned char *)malloc(length);
    memcpy(tlv->value, value, length);

    tlv_value.value = tlv;

    if (key_list_add(tlv_pkt->list, type, tlv_value) != 0)
    {
        free(tlv->value);
        free(tlv);

        return -1;
    }

    tlv_pkt->bytes += sizeof(int) * 2 + length;
    tlv_pkt->count++;

    return 0;
}

int tlv_pkt_add_char(tlv_pkt_t *tlv_pkt, int type, char value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(char));
}

int tlv_pkt_add_short(tlv_pkt_t *tlv_pkt, int type, short value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(short));
}

int tlv_pkt_add_int(tlv_pkt_t *tlv_pkt, int type, int value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(int));
}

int tlv_pkt_add_long(tlv_pkt_t *tlv_pkt, int type, long value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(long));
}

int tlv_pkt_add_uchar(tlv_pkt_t *tlv_pkt, int type, unsigned char value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(unsigned char));
}

int tlv_pkt_add_ushort(tlv_pkt_t *tlv_pkt, int type, unsigned short value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(unsigned short));
}

int tlv_pkt_add_uint(tlv_pkt_t *tlv_pkt, int type, unsigned int value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(unsigned int));
}

int tlv_pkt_add_ulong(tlv_pkt_t *tlv_pkt, int type, unsigned long value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(unsigned long));
}

int tlv_pkt_add_longlong(tlv_pkt_t *tlv_pkt, int type, long long value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(long long));
}

int tlv_pkt_add_float(tlv_pkt_t *tlv_pkt, int type, float value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(float));
}

int tlv_pkt_add_double(tlv_pkt_t *tlv_pkt, int type, double value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, &value, sizeof(double));
}

int tlv_pkt_add_string(tlv_pkt_t *tlv_pkt, int type, char *value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, value, strlen(value) + 1);
}

int tlv_pkt_add_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char *value, int length)
{
    return tlv_pkt_add_raw(tlv_pkt, type, value, length);
}

int tlv_pkt_add_tlv(tlv_pkt_t *tlv_pkt, int type, tlv_pkt_t *value)
{
    return tlv_pkt_add_raw(tlv_pkt, type, value->buffer, value->bytes);
}

int tlv_pkt_serialize(tlv_pkt_t *tlv_pkt)
{
    tlv_t *tlv;

    int offset;
    int count;

    unsigned char *buffer;

    if (tlv_pkt->buffer != NULL)
        return -1;

    offset = 0;
    count = 0;
    buffer = (unsigned char *)malloc(tlv_pkt->bytes);

    KEY_LIST_FOREACH(tlv_pkt->list, node)
    {
        tlv = (tlv_t *)node->value.value;
        memcpy(buffer+offset, &tlv->type, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer+offset, &tlv->length, sizeof(int));
        offset += sizeof(int);
        memcpy(buffer+offset, tlv->value, tlv->length);
        offset += tlv->length;

        count++;
    }

    tlv_pkt->buffer = buffer;
    tlv_pkt->count = count;

    return 0;
}

int tlv_pkt_get_char(tlv_pkt_t *tlv_pkt, int type, char *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(char *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_short(tlv_pkt_t *tlv_pkt, int type, short *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(short *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_int(tlv_pkt_t *tlv_pkt, int type, int *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(int *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_long(tlv_pkt_t *tlv_pkt, int type, long *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(long *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_uchar(tlv_pkt_t *tlv_pkt, int type, unsigned char *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(unsigned char *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_ushort(tlv_pkt_t *tlv_pkt, int type, unsigned short *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(unsigned short *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_uint(tlv_pkt_t *tlv_pkt, int type, unsigned int *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(unsigned int *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_ulong(tlv_pkt_t *tlv_pkt, int type, unsigned long *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(unsigned long *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_longlong(tlv_pkt_t *tlv_pkt, int type, long long *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(long long *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_float(tlv_pkt_t *tlv_pkt, int type, float *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(float *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_double(tlv_pkt_t *tlv_pkt, int type, double *value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = (*(double *)(tlv->value));

    key_list_delete(tlv_pkt->list, type);

    return 0;
}

int tlv_pkt_get_string(tlv_pkt_t *tlv_pkt, int type, char **value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = malloc(tlv->length + 1);

    if (*value == NULL)
        return -1;

    memset(*value, 0, tlv->length + 1);
    memcpy(*value, tlv->value, tlv->length);

    key_list_delete(tlv_pkt->list, type);

    return tlv->length;
}

int tlv_pkt_get_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char **value)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return -1;

    tlv = (tlv_t *)tlv_value.value;
    *value = malloc(tlv->length);

    if (*value == NULL)
        return -1;

    memset(*value, 0, tlv->length);
    memcpy(*value, tlv->value, tlv->length);

    key_list_delete(tlv_pkt->list, type);

    return tlv->length;
}

tlv_pkt_t *tlv_pkt_get_tlv(tlv_pkt_t *tlv_pkt, int type)
{
    tlv_t *tlv;
    value_t tlv_value;

    if (key_list_get(tlv_pkt->list, type, &tlv_value) != 0)
        return NULL;

    tlv = (tlv_t *)tlv_value.value;

    key_list_delete(tlv_pkt->list, type);

    return (tlv_pkt_t *)tlv_pkt_parse(tlv->value, tlv->length);
}