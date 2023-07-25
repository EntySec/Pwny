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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <c2.h>
#include <log.h>
#include <tlv.h>

/*
 * Create TLV packet.
 */

tlv_pkt_t *tlv_channel_pkt(int tlv_channel)
{
    tlv_pkt_t *tlv_pkt = calloc(1, sizeof(*tlv_pkt));

    tlv_pkt->channel = tlv_channel;
    tlv_pkt->pool = API_POOL_BUILTINS;
    tlv_pkt->tag = API_QUIT;
    tlv_pkt->status = API_CALL_SUCCESS;
    tlv_pkt->size = TLV_NO_DATA;
    tlv_pkt->data = NULL;

    return tlv_pkt;
}

/*
 * Send data from TLV transport packet to the TLV transport channel.
 */

void tlv_channel_send(tlv_pkt_t *tlv_pkt)
{
    tlv_pkt_raw_t tlv_raw = tlv_pkt_make_raw(tlv_pkt);

    send(tlv_pkt->channel, tlv_raw.pool, 2, 0);
    send(tlv_pkt->channel, tlv_raw.tag, 2, 0);
    send(tlv_pkt->channel, tlv_raw.status, 2, 0);
    send(tlv_pkt->channel, tlv_raw.size, 4, 0);

    if (tlv_pkt->size > 0)
        send(tlv_pkt->channel, tlv_raw.data, tlv_pkt->size, 0);
}

/*
 * Send data from TLV transport packet to the TLV file descriptor.
 */

void tlv_channel_send_fd(int tlv_fd, tlv_pkt_t *tlv_pkt)
{
    tlv_pkt_raw_t tlv_raw = tlv_pkt_make_raw(tlv_pkt);

    unsigned char tlv_channel[4];
    PACK_INT(tlv_pkt->channel, tlv_channel);

    write(tlv_fd, tlv_channel, 4);

    write(tlv_fd, tlv_raw.pool, 2);
    write(tlv_fd, tlv_raw.tag, 2);
    write(tlv_fd, tlv_raw.status, 2);
    write(tlv_fd, tlv_raw.size, 4);

    if (tlv_pkt->size > 0)
        write(tlv_fd, tlv_raw.data, tlv_pkt->size);
}

/*
 * Send file from TLV transport file to the TLV transport channel.
 */

int tlv_channel_send_file(tlv_pkt_t *tlv_pkt, char *tlv_file)
{
    FILE *fp = fopen(tlv_file, "rb");

    if (fp != NULL)
    {
        int tlv_bytes_read;

        tlv_pkt->status = API_CALL_SUCCESS;
        tlv_pkt->size = TLV_NO_DATA;

        tlv_channel_send(tlv_pkt);

        tlv_pkt->status = API_CALL_WAIT;
        tlv_pkt->data = malloc(TLV_TRANSPORT_CHUNK_SIZE);

        if (tlv_pkt->data != NULL)
        {
            while ((tlv_bytes_read = fread(tlv_pkt->data, 1,
                    TLV_TRANSPORT_CHUNK_SIZE, fp)) > 0)
            {
                tlv_pkt->size = tlv_bytes_read;
                tlv_channel_send(tlv_pkt);

                memset(tlv_pkt->data, 0, TLV_TRANSPORT_CHUNK_SIZE);
            }

            free(tlv_pkt->data);
            return 0;
        }

        fclose(fp);
    }

    return -1;
}

/*
 * Read from TLV file descriptor.
 */

void tlv_channel_read_fd(int tlv_fd, tlv_pkt_t *tlv_pkt, int flag)
{
    unsigned char tlv_channel[4];
    read(tlv_fd, tlv_channel, 4);

    tlv_pkt->channel = UNPACK_INT(tlv_channel);
    tlv_pkt_raw_t tlv_raw;

    read(tlv_fd, tlv_raw.pool, 2);
    read(tlv_fd, tlv_raw.tag, 2);
    read(tlv_fd, tlv_raw.status, 2);
    read(tlv_fd, tlv_raw.size, 4);

    tlv_data_free(tlv_pkt);
    int size = UNPACK_INT(tlv_raw.size);

    if (size > 0)
    {
        if (flag == TLV_NULL)
        {
            tlv_raw.data = malloc(size + 1);

            if (tlv_raw.data != NULL)
            {
                read(tlv_fd, tlv_raw.data, size);
                tlv_raw.data[size] = '\0';
                PACK_INT(size + 1, tlv_raw.size);
            }
        } else
        {
            tlv_raw.data = malloc(size);

            if (tlv_raw.data != NULL)
                read(tlv_fd, tlv_raw.data, size);
        }
    } else
        tlv_raw.data = NULL;

    tlv_pkt_make(tlv_raw, tlv_pkt);
}

/*
 * Read from TLV transport channel.
 */

void tlv_channel_read(tlv_pkt_t *tlv_pkt, int flag)
{
    tlv_pkt_raw_t tlv_raw;

    recv(tlv_pkt->channel, tlv_raw.pool, 2, 0);
    recv(tlv_pkt->channel, tlv_raw.tag, 2, 0);
    recv(tlv_pkt->channel, tlv_raw.status, 2, 0);
    recv(tlv_pkt->channel, tlv_raw.size, 4, 0);

    tlv_data_free(tlv_pkt);
    int size = UNPACK_INT(tlv_raw.size);

    if (size > 0)
    {
        if (flag == TLV_NULL)
        {
            tlv_raw.data = malloc(size + 1);

            if (tlv_raw.data != NULL)
            {
                recv(tlv_pkt->channel, tlv_raw.data, size, 0);
                tlv_raw.data[size] = '\0';
                PACK_INT(size + 1, tlv_raw.size);
            }
        } else
        {
            tlv_raw.data = malloc(size);

            if (tlv_raw.data != NULL)
                recv(tlv_pkt->channel, tlv_raw.data, size, 0);
        }
    } else
        tlv_raw.data = NULL;

    tlv_pkt_make(tlv_raw, tlv_pkt);
}

/*
 * Read argv from TLV transport channel.
 */

int tlv_argv_read(tlv_pkt_t *tlv_pkt, tlv_pkt_t **tlv_argv[], int tlv_argc, int flags)
{
    *tlv_argv = malloc(tlv_argc * sizeof(tlv_pkt_t *));

    if (*tlv_argv == NULL)
        return -1;

    for (int i = 0; i < tlv_argc; i++)
    {
        (*tlv_argv)[i] = tlv_channel_pkt(tlv_pkt->channel);
        tlv_channel_read((*tlv_argv)[i], flags);
        log_debug("* tlv_argv (%d) - (pool: %d, tag: %d, size: %d)\n", i, (*tlv_argv)[i]->pool,
                  (*tlv_argv)[i]->tag, (*tlv_argv)[i]->size);
    }

    return 0;
}

/*
 * Read file from TLV transport channel to fd.
 */

void tlv_channel_read_file_fd(tlv_pkt_t *tlv_pkt, int fd)
{
    tlv_pkt->status = API_CALL_SUCCESS;
    tlv_pkt->size = TLV_NO_DATA;

    tlv_channel_send(tlv_pkt);
    tlv_channel_read(tlv_pkt, TLV_NO_NULL);

    while (tlv_pkt->status == API_CALL_WAIT)
    {
        write(fd, tlv_pkt->data, tlv_pkt->size);
        tlv_channel_read(tlv_pkt, TLV_NO_NULL);
    }
}

/*
 * Read file from TLV transport channel.
 */

int tlv_channel_read_file(tlv_pkt_t *tlv_pkt, char *tlv_file)
{
    FILE *fp = fopen(tlv_file, "wb");

    if (fp != NULL)
    {
        tlv_pkt->status = API_CALL_SUCCESS;
        tlv_pkt->size = TLV_NO_DATA;

        tlv_channel_send(tlv_pkt);
        tlv_channel_read(tlv_pkt, TLV_NO_NULL);

        while (tlv_pkt->status == API_CALL_WAIT)
        {
            fwrite(tlv_pkt->data, sizeof(char), tlv_pkt->size, fp);
            tlv_channel_read(tlv_pkt, TLV_NO_NULL);
        }

        fclose(fp);
        return 0;
    }

    return -1;
}

/*
 * Make readable TLV transport packet from raw TLV transport packet.
 */

void tlv_pkt_make(tlv_pkt_raw_t tlv_raw, tlv_pkt_t *tlv_pkt)
{
    tlv_pkt->pool = UNPACK_SHORT(tlv_raw.pool);
    tlv_pkt->tag = UNPACK_SHORT(tlv_raw.tag);
    tlv_pkt->status = UNPACK_SHORT(tlv_raw.status);
    tlv_pkt->size = UNPACK_INT(tlv_raw.size);
    tlv_pkt->data = tlv_raw.data;
}

/*
 * Make raw TLV transport packet from readable TLV transport packet.
 */

tlv_pkt_raw_t tlv_pkt_make_raw(tlv_pkt_t *tlv_pkt)
{
    tlv_pkt_raw_t tlv_raw;

    PACK_SHORT(tlv_pkt->pool, tlv_raw.pool);
    PACK_SHORT(tlv_pkt->tag, tlv_raw.tag);
    PACK_SHORT(tlv_pkt->status, tlv_raw.status);
    PACK_INT(tlv_pkt->size, tlv_raw.size);
    tlv_raw.data = tlv_pkt->data;

    return tlv_raw;
}

/*
 * Free single TLV transport packet data.
 */

void tlv_data_free(tlv_pkt_t *tlv_pkt)
{
    if (tlv_pkt->size > 0 && tlv_pkt->data != NULL)
    {
        log_debug("* Freeing TLV packet (pool: %d, tag: %d, size: %d)\n",
                  tlv_pkt->pool, tlv_pkt->tag, tlv_pkt->size);

        free(tlv_pkt->data);

        tlv_pkt->size = 0;
        tlv_pkt->data = NULL;
    }
}

/*
 * Free single TLV transport packet.
 */

void tlv_pkt_free(tlv_pkt_t *tlv_pkt)
{
    tlv_data_free(tlv_pkt);
    free(tlv_pkt);
}

/*
 * Free single TLV transport argv.
 */

void tlv_argv_free(tlv_pkt_t *tlv_argv[], int tlv_argc)
{
    for (int i = 0; i < tlv_argc; i++)
        tlv_pkt_free(tlv_argv[i]);

    free(tlv_argv);
}
