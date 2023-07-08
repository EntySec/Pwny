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
#include <tlv.h>

/*
 * Send data from TLV transport packet to the TLV transport channel.
 */

void tlv_channel_send(tlv_pkt_t tlv_packet)
{
    tlv_pkt_raw_t tlv_pkt_new = tlv_pkt_make_raw(tlv_packet);

    send(tlv_packet.tlv_pkt_channel, tlv_pkt_new.tlv_pkt_pool, 2, 0);
    send(tlv_packet.tlv_pkt_channel, tlv_pkt_new.tlv_pkt_tag, 2, 0);
    send(tlv_packet.tlv_pkt_channel, tlv_pkt_new.tlv_pkt_status, 2, 0);
    send(tlv_packet.tlv_pkt_channel, tlv_pkt_new.tlv_pkt_size, 4, 0);

    if (tlv_packet.tlv_pkt_size > 0)
        send(tlv_packet.tlv_pkt_channel, tlv_pkt_new.tlv_pkt_data, tlv_packet.tlv_pkt_size, 0);
}

/*
 * Send data from TLV transport packet to the TLV file descriptor.
 */

void tlv_channel_send_fd(int tlv_fd, tlv_pkt_t tlv_packet)
{
    tlv_pkt_raw_t tlv_pkt_new = tlv_pkt_make_raw(tlv_packet);

    char tlv_channel[4];
    PACK_INT(tlv_packet.tlv_pkt_channel, tlv_channel);

    write(tlv_fd, tlv_channel, 4);

    write(tlv_fd, tlv_pkt_new.tlv_pkt_pool, 2);
    write(tlv_fd, tlv_pkt_new.tlv_pkt_tag, 2);
    write(tlv_fd, tlv_pkt_new.tlv_pkt_status, 2);
    write(tlv_fd, tlv_pkt_new.tlv_pkt_size, 4);

    if (tlv_packet.tlv_pkt_size > 0)
        write(tlv_fd, tlv_pkt_new.tlv_pkt_data, tlv_packet.tlv_pkt_size);
}

/*
 * Send file from TLV transport file to the TLV transport channel.
 */

int tlv_channel_send_file(tlv_pkt_t tlv_packet, tlv_file_t tlv_file_new)
{
    FILE *fp = fopen(tlv_file_new.tlv_file_from, "rb");

    if (fp != NULL)
    {
        int tlv_bytes_read;

        tlv_pkt_t tlv_pkt_new = {
            .tlv_pkt_channel = tlv_packet.tlv_pkt_channel,
            .tlv_pkt_pool = tlv_packet.tlv_pkt_pool,
            .tlv_pkt_tag = tlv_packet.tlv_pkt_tag,
            .tlv_pkt_status = API_CALL_SUCCESS,
            .tlv_pkt_size = 0,
        };

        tlv_channel_send(tlv_pkt_new);

        tlv_pkt_new.tlv_pkt_status = API_CALL_WAIT;
        tlv_pkt_new.tlv_pkt_data = malloc(TLV_TRANSPORT_CHUNK_SIZE);

        if (tlv_pkt_new.tlv_pkt_data != NULL)
        {
            while ((tlv_bytes_read = fread(tlv_pkt_new.tlv_pkt_data, 1,
                    TLV_TRANSPORT_CHUNK_SIZE, fp)) > 0)
            {
                tlv_pkt_new.tlv_pkt_size = tlv_bytes_read;
                tlv_channel_send(tlv_pkt_new);

                memset(tlv_pkt_new.tlv_pkt_data, 0, TLV_TRANSPORT_CHUNK_SIZE);
            }

            tlv_pkt_free(tlv_pkt_new);
            return 0;
        }

        fclose(fp);
    }

    return -1;
}

/*
 * Read from TLV file descriptor.
 */

tlv_pkt_t tlv_channel_read_fd(int tlv_fd, int flag)
{
    char tlv_channel[4];
    read(tlv_fd, tlv_channel, 4);

    tlv_pkt_raw_t tlv_pkt_new = {
        .tlv_pkt_channel = UNPACK_INT(tlv_channel),
    };

    read(tlv_fd, tlv_pkt_new.tlv_pkt_pool, 2);
    read(tlv_fd, tlv_pkt_new.tlv_pkt_tag, 2);
    read(tlv_fd, tlv_pkt_new.tlv_pkt_status, 2);
    read(tlv_fd, tlv_pkt_new.tlv_pkt_size, 4);

    int size = UNPACK_INT(tlv_pkt_new.tlv_pkt_size);

    if (size > 0)
    {
        if (flag == TLV_NULL)
        {
            tlv_pkt_new.tlv_pkt_data = malloc(size + 1);

            if (tlv_pkt_new.tlv_pkt_data != NULL)
            {
                read(tlv_fd, tlv_pkt_new.tlv_pkt_data, size);
                tlv_pkt_new.tlv_pkt_data[size] = '\0';
            }
        } else
        {
            tlv_pkt_new.tlv_pkt_data = malloc(size);

            if (tlv_pkt_new.tlv_pkt_data != NULL)
                read(tlv_fd, tlv_pkt_new.tlv_pkt_data, size);
        }
    }

    return tlv_pkt_make(tlv_pkt_new);
}

/*
 * Read from TLV transport channel.
 */

tlv_pkt_t tlv_channel_read(int tlv_channel, int flag)
{
    tlv_pkt_raw_t tlv_pkt_new = {
        .tlv_pkt_channel = tlv_channel,
    };

    recv(tlv_channel, tlv_pkt_new.tlv_pkt_pool, 2, 0);
    recv(tlv_channel, tlv_pkt_new.tlv_pkt_tag, 2, 0);
    recv(tlv_channel, tlv_pkt_new.tlv_pkt_status, 2, 0);
    recv(tlv_channel, tlv_pkt_new.tlv_pkt_size, 4, 0);

    int size = UNPACK_INT(tlv_pkt_new.tlv_pkt_size);

    if (size > 0)
    {
        if (flag == TLV_NULL)
        {
            tlv_pkt_new.tlv_pkt_data = malloc(size + 1);

            if (tlv_pkt_new.tlv_pkt_data != NULL)
            {
                recv(tlv_channel, tlv_pkt_new.tlv_pkt_data, size, 0);
                tlv_pkt_new.tlv_pkt_data[size] = 0;
            }
        } else
        {
            tlv_pkt_new.tlv_pkt_data = malloc(size);

            if (tlv_pkt_new.tlv_pkt_data != NULL)
                recv(tlv_channel, tlv_pkt_new.tlv_pkt_data, size, 0);
        }
    }

    return tlv_pkt_make(tlv_pkt_new);
}

/*
 * Read argv from TLV transport channel.
 */

int tlv_argv_read(tlv_pkt_t tlv_packet, tlv_pkt_t **tlv_argv, int tlv_argc, int append_zero_byte)
{
    *tlv_argv = malloc(tlv_argc * sizeof(tlv_pkt_t));

    if (*tlv_argv == NULL)
        return -1;

    for (int i = 0; i < tlv_argc; i++)
    {
        if (append_zero_byte)
            (*tlv_argv)[i] = tlv_channel_read(tlv_packet.tlv_pkt_channel, TLV_NULL);
        else
            (*tlv_argv)[i] = tlv_channel_read(tlv_packet.tlv_pkt_channel, TLV_NO_NULL);
    }

    return 0;
}

/*
 * Read file from TLV transport channel.
 */

int tlv_channel_read_file(tlv_pkt_t tlv_packet, tlv_file_t tlv_file_new)
{
    FILE *fp = fopen(tlv_file_new.tlv_file_to, "wb");

    if (fp != NULL)
    {
        tlv_pkt_t tlv_pkt_new = {
            .tlv_pkt_channel = tlv_packet.tlv_pkt_channel,
            .tlv_pkt_pool = tlv_packet.tlv_pkt_pool,
            .tlv_pkt_tag = tlv_packet.tlv_pkt_tag,
            .tlv_pkt_status = API_CALL_SUCCESS,
            .tlv_pkt_size = 0,
        };

        tlv_channel_send(tlv_pkt_new);
        tlv_pkt_t tlv_pkt_file = tlv_channel_read(
            tlv_pkt_new.tlv_pkt_channel, 0);

        while (tlv_pkt_file.tlv_pkt_status == API_CALL_WAIT)
        {
            fwrite(tlv_pkt_file.tlv_pkt_data, sizeof(char), tlv_pkt_file.tlv_pkt_size, fp);
            memset(tlv_pkt_file.tlv_pkt_data, 0, tlv_pkt_file.tlv_pkt_size);
            tlv_pkt_file = tlv_channel_read(tlv_pkt_new.tlv_pkt_channel, 0);
        }

        tlv_pkt_free(tlv_pkt_file);

        fclose(fp);
        return 0;
    }

    return -1;
}

/*
 * Make readable TLV transport packet from raw TLV transport packet.
 */

tlv_pkt_t tlv_pkt_make(tlv_pkt_raw_t tlv_packet)
{
    tlv_pkt_t tlv_pkt_new = {
        .tlv_pkt_channel = tlv_packet.tlv_pkt_channel,
        .tlv_pkt_pool = UNPACK_SHORT(tlv_packet.tlv_pkt_pool),
        .tlv_pkt_tag = UNPACK_SHORT(tlv_packet.tlv_pkt_tag),
        .tlv_pkt_status = UNPACK_SHORT(tlv_packet.tlv_pkt_status),
        .tlv_pkt_size = UNPACK_INT(tlv_packet.tlv_pkt_size),
        .tlv_pkt_data = tlv_packet.tlv_pkt_data,
    };

    return tlv_pkt_new;
}

/*
 * Make raw TLV transport packet from readable TLV transport packet.
 */

tlv_pkt_raw_t tlv_pkt_make_raw(tlv_pkt_t tlv_packet)
{
    tlv_pkt_raw_t tlv_pkt_new = {
        .tlv_pkt_channel = tlv_packet.tlv_pkt_channel,
    };

    PACK_SHORT(tlv_packet.tlv_pkt_pool, tlv_pkt_new.tlv_pkt_pool);
    PACK_SHORT(tlv_packet.tlv_pkt_tag, tlv_pkt_new.tlv_pkt_tag);
    PACK_SHORT(tlv_packet.tlv_pkt_status, tlv_pkt_new.tlv_pkt_status);
    PACK_INT(tlv_packet.tlv_pkt_size, tlv_pkt_new.tlv_pkt_size);
    tlv_pkt_new.tlv_pkt_data = tlv_packet.tlv_pkt_data;

    return tlv_pkt_new;
}

/*
 * Free single TLV transport packet.
 */

void tlv_pkt_free(tlv_pkt_t tlv_packet)
{
    if (tlv_packet.tlv_pkt_size > 0)
        free(tlv_packet.tlv_pkt_data);
}

/*
 * Free single TLV transport argv.
 */

void tlv_argv_free(tlv_pkt_t *tlv_argv, int tlv_argc)
{
    for (int i = 0; i < tlv_argc; i++)
        tlv_pkt_free(tlv_argv[i]);

    free(tlv_argv);
}

/*
 * Close TLV transport channel.
 */

void tlv_channel_close(int tlv_channel)
{
    #ifndef _WIN32
    close(tlv_channel);
    #else
    closesocket(tlv_channel);
    #endif
}
