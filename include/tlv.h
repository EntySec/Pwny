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
} tlv_pkt_t;

tlv_pkt_t *tlv_pkt_create(void);
tlv_pkt_t *tlv_pkt_parse(unsigned char *, int);

int tlv_pkt_write(int, tlv_pkt_t *);
int tlv_pkt_read(int, tlv_pkt_t *);

void tlv_pkt_destroy(tlv_pkt_t *);
int tlv_pkt_serialize(tlv_pkt_t *);

int tlv_pkt_add_raw(tlv_pkt_t *, int, void *, int);

int tlv_pkt_add_char(tlv_pkt_t *, int, char);
int tlv_pkt_add_short(tlv_pkt_t *, int, short);
int tlv_pkt_add_int(tlv_pkt_t *, int, int);
int tlv_pkt_add_long(tlv_pkt_t *, int, long);

int tlv_pkt_add_uchar(tlv_pkt_t *, int, unsigned char);
int tlv_pkt_add_ushort(tlv_pkt_t *, int, unsigned short);
int tlv_pkt_add_uint(tlv_pkt_t *, int, unsigned int);
int tlv_pkt_add_ulong(tlv_pkt_t *, int, unsigned long);

int tlv_pkt_add_longlong(tlv_pkt_t *, int, long long);
int tlv_pkt_add_float(tlv_pkt_t *, int, float);
int tlv_pkt_add_double(tlv_pkt_t *, int, double);
int tlv_pkt_add_string(tlv_pkt_t *, int, char *);
int tlv_pkt_add_bytes(tlv_pkt_t *, int, unsigned char *, int);
int tlv_pkt_add_tlv(tlv_pkt_t *, int, tlv_pkt_t *);

int tlv_pkt_get_char(tlv_pkt_t *, int, char *);
int tlv_pkt_get_short(tlv_pkt_t *, int, short *);
int tlv_pkt_get_int(tlv_pkt_t *, int, int *);
int tlv_pkt_get_long(tlv_pkt_t *, int, long *);

int tlv_pkt_get_uchar(tlv_pkt_t *, int, unsigned char *);
int tlv_pkt_get_ushort(tlv_pkt_t *, int, unsigned short *);
int tlv_pkt_get_uint(tlv_pkt_t *, int, unsigned int *);
int tlv_pkt_get_ulong(tlv_pkt_t *, int, unsigned long *);

int tlv_pkt_get_longlong(tlv_pkt_t *, int, long long *);
int tlv_pkt_get_float(tlv_pkt_t *, int, float *);
int tlv_pkt_get_double(tlv_pkt_t *, int, double *);
int tlv_pkt_get_string(tlv_pkt_t *, int, char **);
int tlv_pkt_get_bytes(tlv_pkt_t *, int, unsigned char **);
tlv_pkt_t *tlv_pkt_get_object(tlv_pkt_t *, int);

#endif /* _TLV_H_ */