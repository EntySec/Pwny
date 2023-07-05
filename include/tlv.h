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

#ifndef WINDOWS
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

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

/*
 * Primary channel structure here
 */

typedef struct tlv_transport_channel {
    #ifndef WINDOWS
    int tlv_transport_channel_pipe;
    #else
    SOCKET tlv_transport_channel_pipe;
    #endif

    int tlv_transport_channel_host;
    int tlv_transport_channel_port;
} tlv_transport_channel_t;

typedef struct tlv_transport_pkt_raw {
    tlv_transport_channel_t *tlv_transport_pkt_channel;
    char tlv_transport_pkt_scope[2];
    char tlv_transport_pkt_tag[2];
    char tlv_transport_pkt_status[2];
    char tlv_transport_pkt_size[4];
    char *tlv_transport_pkt_data;
} tlv_transport_pkt_raw_t;

typedef struct tlv_transport_pkt {
    tlv_transport_channel_t *tlv_transport_pkt_channel;
    int tlv_transport_pkt_scope;
    int tlv_transport_pkt_tag;
    int tlv_transport_pkt_status;
    int tlv_transport_pkt_size;
    char *tlv_transport_pkt_data;
} tlv_transport_pkt_t;

typedef struct tlv_transport_file {
    char *tlv_transport_file_to;
    char *tlv_transport_file_from;
} tlv_transport_file_t;

tlv_transport_pkt_t tlv_transport_pkt_make(tlv_transport_pkt_raw_t);
tlv_transport_pkt_raw_t tlv_transport_pkt_make_raw(tlv_transport_pkt_t);

/*
 * Channel control methods here
 */

int tlv_transport_channel_open(tlv_transport_channel_t *);
int tlv_transport_channel_listen(tlv_transport_channel_t *);
void tlv_transport_channel_close(tlv_transport_channel_t *);

/*
 * Channel I/O methods here
 */

void tlv_transport_channel_send(tlv_transport_pkt_t);
tlv_transport_pkt_t tlv_transport_channel_read(tlv_transport_channel_t *, int);

int tlv_transport_argv_read(tlv_transport_channel_t *, tlv_transport_pkt_t **, int, int);

/*
 * Channel FI/FO methods here
 */

int tlv_transport_channel_send_file(tlv_transport_pkt_t, tlv_transport_file_t);
int tlv_transport_channel_read_file(tlv_transport_pkt_t, tlv_transport_file_t);

void tlv_transport_channel_read_file_fd(tlv_transport_pkt_t, int);

/*
 * Clean up methods here
 */

void tlv_transport_pkt_free(tlv_transport_pkt_t);
void tlv_transport_argv_free(tlv_transport_pkt_t *, int);

#endif /* _TLV_H_ */
