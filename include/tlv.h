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

/*
 * Pre-defined macros here
 */

#define TLV_TRANSPORT_CHUNK_SIZE 1024

#define PACK_SHORT(val, val_pkt) val_pkt[1] = (val >> 8) & 0xff; \
        val_pkt[0] = val & 0xff
#define UNPACK_SHORT(val_pkt) val_pkt[0] | val_pkt[1] << 8

#define PACK_INT(val, val_pkt) val_pkt[3] = (val >> 24) & 0xff; \
        val_pkt[2] = (val >> 16) & 0xff; \
        val_pkt[1] = (val >> 8) & 0xff; \
        val_pkt[0] = val & 0xff
#define UNPACK_INT(val_pkt) val_pkt[0] | val_pkt[1] << 8 | val_pkt[2] << 16 | val_pkt[3] << 24

#define TLV_NULL 1
#define TLV_NO_NULL 0
#define TLV_NO_DATA 0

#define TLV_NO_CHANNEL -1

typedef struct tlv_pkt_raw {
    unsigned char tlv_pkt_pool[2];
    unsigned char tlv_pkt_tag[2];
    unsigned char tlv_pkt_status[2];
    unsigned char tlv_pkt_size[4];
    char *tlv_pkt_data;
} tlv_pkt_raw_t;

typedef struct tlv_pkt {
    int tlv_pkt_channel;
    int tlv_pkt_pool;
    int tlv_pkt_tag;
    int tlv_pkt_status;
    int tlv_pkt_size;
    char *tlv_pkt_data;
} tlv_pkt_t;

typedef struct tlv_file {
    char *tlv_file_to;
    char *tlv_file_from;
} tlv_file_t;

tlv_pkt_t *tlv_channel_pkt(int);

void tlv_pkt_make(tlv_pkt_raw_t, tlv_pkt_t *);
tlv_pkt_raw_t tlv_pkt_make_raw(tlv_pkt_t *);

/*
 * Channel control methods here
 */

void tlv_channel_close(tlv_pkt_t *);

/*
 * Channel I/O methods here
 */

void tlv_channel_send(tlv_pkt_t *);
void tlv_channel_send_fd(int, tlv_pkt_t *);

void tlv_channel_read(tlv_pkt_t *, int);
void tlv_channel_read_fd(int, tlv_pkt_t *, int);

int tlv_argv_read(tlv_pkt_t *, tlv_pkt_t **[], int, int);

/*
 * Channel FI/FO methods here
 */

int tlv_channel_send_file(tlv_pkt_t *, tlv_file_t);
int tlv_channel_read_file(tlv_pkt_t *, tlv_file_t);

/*
 * Clean up methods here
 */

void tlv_data_free(tlv_pkt_t *);
void tlv_pkt_free(tlv_pkt_t *);
void tlv_argv_free(tlv_pkt_t *[], int);

#endif /* _TLV_H_ */
