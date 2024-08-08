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

#ifndef _TLV_H_
#define _TLV_H_

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include <queue.h>
#include <crypt.h>

#define TLV_FIELD  4
#define TLV_HEADER 8

#ifdef __linux__
#define ntohll(x) (((uint64_t)(ntohl((int)((x << 32) >> 32))) << 32) | (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)
#endif

struct tlv_header
{
    int type;
    int length;
} __attribute__((packed));

typedef struct
{
    unsigned char *buffer;
    int bytes;
    int count;
} tlv_pkt_t;

tlv_pkt_t *tlv_pkt_create(void);
void tlv_pkt_destroy(tlv_pkt_t *tlv_pkt);

int tlv_pkt_add_raw(tlv_pkt_t *tlv_pkt, int type, void *value, size_t length);

int tlv_pkt_add_u16(tlv_pkt_t *tlv_pkt, int type, int16_t value);
int tlv_pkt_add_u32(tlv_pkt_t *tlv_pkt, int type, int32_t value);
int tlv_pkt_add_u64(tlv_pkt_t *tlv_pkt, int type, int64_t value);

int tlv_pkt_add_string(tlv_pkt_t *tlv_pkt, int type, char *value);
int tlv_pkt_add_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char *value, size_t length);
int tlv_pkt_add_tlv(tlv_pkt_t *tlv_pkt, int type, tlv_pkt_t *value);

ssize_t tlv_pkt_get_u16(tlv_pkt_t *tlv_pkt, int type, int16_t *value);
ssize_t tlv_pkt_get_u32(tlv_pkt_t *tlv_pkt, int type, int32_t *value);
ssize_t tlv_pkt_get_u64(tlv_pkt_t *tlv_pkt, int type, int64_t *value);

ssize_t tlv_pkt_get_string(tlv_pkt_t *tlv_pkt, int type, char *value);
ssize_t tlv_pkt_get_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char **value);
ssize_t tlv_pkt_get_tlv(tlv_pkt_t *tlv_pkt, int type, tlv_pkt_t **value);

#endif
