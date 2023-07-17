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
    tlv_pkt_t *tlv_packet = calloc(1, sizeof(*tlv_packet));

    tlv_packet->tlv_pkt_channel = tlv_channel;
    tlv_packet->tlv_pkt_pool = API_POOL_BUILTINS;
    tlv_packet->tlv_pkt_tag = API_QUIT;
    tlv_packet->tlv_pkt_status = API_CALL_SUCCESS;
    tlv_packet->tlv_pkt_size = TLV_NO_DATA;
    tlv_packet->tlv_pkt_data = NULL;

    return tlv_packet;
}

/*
 * Send data from TLV transport packet to the TLV transport channel.
 */

void tlv_channel_send(tlv_pkt_t *tlv_packet)
{
    tlv_pkt_raw_t tlv_raw = tlv_pkt_make_raw(tlv_packet);

    send(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_pool, 2, 0);
    send(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_tag, 2, 0);
    send(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_status, 2, 0);
    send(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_size, 4, 0);

    if (tlv_packet->tlv_pkt_size > 0)
        send(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_data, tlv_packet->tlv_pkt_size, 0);
}

/*
 * Send data from TLV transport packet to the TLV file descriptor.
 */

void tlv_channel_send_fd(int tlv_fd, tlv_pkt_t *tlv_packet)
{
    tlv_pkt_raw_t tlv_raw = tlv_pkt_make_raw(tlv_packet);

    unsigned char tlv_channel[4];
    PACK_INT(tlv_packet->tlv_pkt_channel, tlv_channel);

    write(tlv_fd, tlv_channel, 4);

    write(tlv_fd, tlv_raw.tlv_pkt_pool, 2);
    write(tlv_fd, tlv_raw.tlv_pkt_tag, 2);
    write(tlv_fd, tlv_raw.tlv_pkt_status, 2);
    write(tlv_fd, tlv_raw.tlv_pkt_size, 4);

    if (tlv_packet->tlv_pkt_size > 0)
        write(tlv_fd, tlv_raw.tlv_pkt_data, tlv_packet->tlv_pkt_size);
}

/*
 * Send file from TLV transport file to the TLV transport channel.
 */

int tlv_channel_send_file(tlv_pkt_t *tlv_packet, tlv_file_t tlv_file_new)
{
    FILE *fp = fopen(tlv_file_new.tlv_file_from, "rb");

    if (fp != NULL)
    {
        int tlv_bytes_read;

        tlv_packet->tlv_pkt_status = API_CALL_SUCCESS;
        tlv_packet->tlv_pkt_size = TLV_NO_DATA;

        tlv_channel_send(tlv_packet);

        tlv_packet->tlv_pkt_status = API_CALL_WAIT;
        tlv_packet->tlv_pkt_data = malloc(TLV_TRANSPORT_CHUNK_SIZE);

        if (tlv_packet->tlv_pkt_data != NULL)
        {
            while ((tlv_bytes_read = fread(tlv_packet->tlv_pkt_data, 1,
                    TLV_TRANSPORT_CHUNK_SIZE, fp)) > 0)
            {
                tlv_packet->tlv_pkt_size = tlv_bytes_read;
                tlv_channel_send(tlv_packet);

                memset(tlv_packet->tlv_pkt_data, 0, TLV_TRANSPORT_CHUNK_SIZE);
            }

            free(tlv_packet->tlv_pkt_data);
            return 0;
        }

        fclose(fp);
    }

    return -1;
}

/*
 * Read from TLV file descriptor.
 */

void tlv_channel_read_fd(int tlv_fd, tlv_pkt_t *tlv_packet, int flag)
{
    unsigned char tlv_channel[4];
    read(tlv_fd, tlv_channel, 4);

    tlv_packet->tlv_pkt_channel = UNPACK_INT(tlv_channel);
    tlv_pkt_raw_t tlv_raw;

    read(tlv_fd, tlv_raw.tlv_pkt_pool, 2);
    read(tlv_fd, tlv_raw.tlv_pkt_tag, 2);
    read(tlv_fd, tlv_raw.tlv_pkt_status, 2);
    read(tlv_fd, tlv_raw.tlv_pkt_size, 4);

    tlv_data_free(tlv_packet);
    int size = UNPACK_INT(tlv_raw.tlv_pkt_size);

    if (size > 0)
    {
        if (flag == TLV_NULL)
        {
            tlv_raw.tlv_pkt_data = malloc(size + 1);

            if (tlv_raw.tlv_pkt_data != NULL)
            {
                read(tlv_fd, tlv_raw.tlv_pkt_data, size);
                tlv_raw.tlv_pkt_data[size] = '\0';
                PACK_INT(size + 1, tlv_raw.tlv_pkt_size);
            }
        } else
        {
            tlv_raw.tlv_pkt_data = malloc(size);

            if (tlv_raw.tlv_pkt_data != NULL)
                read(tlv_fd, tlv_raw.tlv_pkt_data, size);
        }
    } else
        tlv_raw.tlv_pkt_data = NULL;

    tlv_pkt_make(tlv_raw, tlv_packet);
}

/*
 * Read from TLV transport channel.
 */

void tlv_channel_read(tlv_pkt_t *tlv_packet, int flag)
{
    tlv_pkt_raw_t tlv_raw;

    recv(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_pool, 2, 0);
    recv(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_tag, 2, 0);
    recv(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_status, 2, 0);
    recv(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_size, 4, 0);

    tlv_data_free(tlv_packet);
    int size = UNPACK_INT(tlv_raw.tlv_pkt_size);

    if (size > 0)
    {
        if (flag == TLV_NULL)
        {
            tlv_raw.tlv_pkt_data = malloc(size + 1);

            if (tlv_raw.tlv_pkt_data != NULL)
            {
                recv(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_data, size, 0);
                tlv_raw.tlv_pkt_data[size] = '\0';
                PACK_INT(size + 1, tlv_raw.tlv_pkt_size);
            }
        } else
        {
            tlv_raw.tlv_pkt_data = malloc(size);

            if (tlv_raw.tlv_pkt_data != NULL)
                recv(tlv_packet->tlv_pkt_channel, tlv_raw.tlv_pkt_data, size, 0);
        }
    } else
        tlv_raw.tlv_pkt_data = NULL;

    tlv_pkt_make(tlv_raw, tlv_packet);
}

/*
 * Read argv from TLV transport channel.
 */

int tlv_argv_read(tlv_pkt_t *tlv_packet, tlv_pkt_t **tlv_argv[], int tlv_argc, int flags)
{
    *tlv_argv = malloc(tlv_argc * sizeof(tlv_pkt_t *));

    if (*tlv_argv == NULL)
        return -1;

    for (int i = 0; i < tlv_argc; i++)
    {
        (*tlv_argv)[i] = tlv_channel_pkt(tlv_packet->tlv_pkt_channel);
        tlv_channel_read((*tlv_argv)[i], flags);
        log_debug("* tlv_argv (%d) - (pool: %d, tag: %d, size: %d)\n", i, (*tlv_argv)[i]->tlv_pkt_pool,
                  (*tlv_argv)[i]->tlv_pkt_tag, (*tlv_argv)[i]->tlv_pkt_size);
    }

    return 0;
}

/*
 * Read file from TLV transport channel.
 */

int tlv_channel_read_file(tlv_pkt_t *tlv_packet, tlv_file_t tlv_file_new)
{
    FILE *fp = fopen(tlv_file_new.tlv_file_to, "wb");

    if (fp != NULL)
    {
        tlv_packet->tlv_pkt_status = API_CALL_SUCCESS;
        tlv_packet->tlv_pkt_size = TLV_NO_DATA;

        tlv_channel_send(tlv_packet);
        tlv_channel_read(tlv_packet, TLV_NO_NULL);

        while (tlv_packet->tlv_pkt_status == API_CALL_WAIT)
        {
            fwrite(tlv_packet->tlv_pkt_data, sizeof(char), tlv_packet->tlv_pkt_size, fp);
            tlv_channel_read(tlv_packet, TLV_NO_NULL);
        }

        fclose(fp);
        return 0;
    }

    return -1;
}

/*
 * Make readable TLV transport packet from raw TLV transport packet.
 */

void tlv_pkt_make(tlv_pkt_raw_t tlv_raw, tlv_pkt_t *tlv_packet)
{
    tlv_packet->tlv_pkt_pool = UNPACK_SHORT(tlv_raw.tlv_pkt_pool);
    tlv_packet->tlv_pkt_tag = UNPACK_SHORT(tlv_raw.tlv_pkt_tag);
    tlv_packet->tlv_pkt_status = UNPACK_SHORT(tlv_raw.tlv_pkt_status);
    tlv_packet->tlv_pkt_size = UNPACK_INT(tlv_raw.tlv_pkt_size);
    tlv_packet->tlv_pkt_data = tlv_raw.tlv_pkt_data;
}

/*
 * Make raw TLV transport packet from readable TLV transport packet.
 */

tlv_pkt_raw_t tlv_pkt_make_raw(tlv_pkt_t *tlv_packet)
{
    tlv_pkt_raw_t tlv_raw;

    PACK_SHORT(tlv_packet->tlv_pkt_pool, tlv_raw.tlv_pkt_pool);
    PACK_SHORT(tlv_packet->tlv_pkt_tag, tlv_raw.tlv_pkt_tag);
    PACK_SHORT(tlv_packet->tlv_pkt_status, tlv_raw.tlv_pkt_status);
    PACK_INT(tlv_packet->tlv_pkt_size, tlv_raw.tlv_pkt_size);
    tlv_raw.tlv_pkt_data = tlv_packet->tlv_pkt_data;

    return tlv_raw;
}

/*
 * Close TLV transport channel.
 */

void tlv_channel_close(tlv_pkt_t *tlv_packet)
{
    close(tlv_packet->tlv_pkt_channel);
}


/*
 * Free single TLV transport packet data.
 */

void tlv_data_free(tlv_pkt_t *tlv_packet)
{
    if (tlv_packet->tlv_pkt_size > 0 && tlv_packet->tlv_pkt_data != NULL)
    {
        log_debug("* Freeing TLV packet (pool: %d, tag: %d, size: %d)\n", tlv_packet->tlv_pkt_pool,
                  tlv_packet->tlv_pkt_tag, tlv_packet->tlv_pkt_size);

        free(tlv_packet->tlv_pkt_data);

        tlv_packet->tlv_pkt_size = 0;
        tlv_packet->tlv_pkt_data = NULL;
    }
}

/*
 * Free single TLV transport packet.
 */

void tlv_pkt_free(tlv_pkt_t *tlv_packet)
{
    tlv_data_free(tlv_packet);
    free(tlv_packet);
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
