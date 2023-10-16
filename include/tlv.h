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

#ifndef _TLV_H_
#define _TLV_H_

#include <key_list.h>

typedef struct
{
    int type;
    int length;
    unsigned char *value;
} tlv_t;

typedef struct
{
    key_list_t *list;
    unsigned char *buffer;
    int bytes;
    int count;
} tlv_pkt_t;

tlv_pkt_t *tlv_pkt_create(void);
tlv_pkt_t *tlv_pkt_parse(unsigned char *buffer, int size);

int tlv_pkt_write(int fd, tlv_pkt_t *tlv_pkt);
int tlv_pkt_read(int fd, tlv_pkt_t *tlv_pkt);

void tlv_pkt_destroy(tlv_pkt_t *tlv_pkt);
int tlv_pkt_serialize(tlv_pkt_t *tlv_pkt);

int tlv_pkt_add_raw(tlv_pkt_t *tlv_pkt, int type, void *value, int length);

int tlv_pkt_add_char(tlv_pkt_t *tlv_pkt, int type, char value);
int tlv_pkt_add_short(tlv_pkt_t *tlv_pkt, int type, short value);
int tlv_pkt_add_int(tlv_pkt_t *tlv_pkt, int type, int value);
int tlv_pkt_add_long(tlv_pkt_t *tlv_pkt, int type, long value);

int tlv_pkt_add_uchar(tlv_pkt_t *tlv_pkt, int type, unsigned char value);
int tlv_pkt_add_ushort(tlv_pkt_t *tlv_pkt, int type, unsigned short value);
int tlv_pkt_add_uint(tlv_pkt_t *tlv_pkt, int type, unsigned int value);
int tlv_pkt_add_ulong(tlv_pkt_t *tlv_pkt, int type, unsigned long value);

int tlv_pkt_add_longlong(tlv_pkt_t *tlv_pkt, int type, long long value);
int tlv_pkt_add_float(tlv_pkt_t *tlv_pkt, int type, float value);
int tlv_pkt_add_double(tlv_pkt_t *tlv_pkt, int type, double value);
int tlv_pkt_add_string(tlv_pkt_t *tlv_pkt, int type, char *value);
int tlv_pkt_add_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char *value, int length);
int tlv_pkt_add_tlv(tlv_pkt_t *tlv_pkt, int type, tlv_pkt_t *value);

int tlv_pkt_get_char(tlv_pkt_t *tlv_pkt, int type, char *value);
int tlv_pkt_get_short(tlv_pkt_t *tlv_pkt, int type, short *value);
int tlv_pkt_get_int(tlv_pkt_t *tlv_pkt, int type, int *value);
int tlv_pkt_get_long(tlv_pkt_t *tlv_pkt, int type, long *value);

int tlv_pkt_get_uchar(tlv_pkt_t *tlv_pkt, int type, unsigned char *value);
int tlv_pkt_get_ushort(tlv_pkt_t *tlv_pkt, int type, unsigned short *value);
int tlv_pkt_get_uint(tlv_pkt_t *tlv_pkt, int type, unsigned int *value);
int tlv_pkt_get_ulong(tlv_pkt_t *tlv_pkt, int type, unsigned long *value);

int tlv_pkt_get_longlong(tlv_pkt_t *tlv_pkt, int type, long long *value);
int tlv_pkt_get_float(tlv_pkt_t *tlv_pkt, int type, float *value);
int tlv_pkt_get_double(tlv_pkt_t *tlv_pkt, int type, double *value);
int tlv_pkt_get_string(tlv_pkt_t *tlv_pkt, int type, char *value);
int tlv_pkt_get_bytes(tlv_pkt_t *tlv_pkt, int type, unsigned char **value);
tlv_pkt_t *tlv_pkt_get_object(tlv_pkt_t *tlv_pkt, int type);

#endif