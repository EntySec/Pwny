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

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include "c2.h"
#include "tlv.h"

int tlv_transport_channel_open(tlv_transport_channel_t *tlv_transport_channel_new)
{
    #ifndef WINDOWS
    tlv_transport_channel_new->tlv_transport_channel_pipe = socket(AF_INET, SOCK_STREAM, 0);
    if (tlv_transport_channel_new->tlv_transport_channel_pipe == -1)
        return -1;

    struct sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(tlv_transport_channel_new->tlv_transport_channel_port);
    hint.sin_addr.s_addr = tlv_transport_channel_new->tlv_transport_channel_host;

    if (connect(tlv_transport_channel_new->tlv_transport_channel_pipe,
        (struct sockaddr *)&hint, sizeof(hint)) != 0)
        return -1;

    #else
    WSADATA wsadata;

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
        return -1;

    tlv_transport_channel_new->tlv_transport_channel_pipe = socket(AF_INET, SOCK_STREAM, 0);
    if (tlv_transport_channel_new->tlv_transport_channel_pipe == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    SOCKADDR_IN hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(tlv_transport_channel_new->tlv_transport_channel_port);
    hint.sin_addr.s_addr = tlv_transport_channel_new->tlv_transport_channel_host;

    if (connect(tlv_transport_channel_new->tlv_transport_channel_pipe,
        (SOCKADDR *)&hint, sizeof(hint)) != 0) {
        closesocket(tlv_transport_channel_new->tlv_transport_channel_pipe);
        WSACleanup();
        return -1;
    }
    #endif

    return 0;
}

int tlv_transport_channel_listen(tlv_transport_channel_t *tlv_transport_channel_new)
{
    #ifndef WINDOWS
    tlv_transport_channel_new->tlv_transport_channel_pipe = socket(AF_INET, SOCK_STREAM, 0);

    if (tlv_transport_channel_new->tlv_transport_channel_pipe == -1)
        return -1;

    struct sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_addr.s_addr = tlv_transport_channel_new->tlv_transport_channel_host;
    hint.sin_port = htons(tlv_transport_channel_new->tlv_transport_channel_port);

    if (bind(tlv_transport_channel_new->tlv_transport_channel_pipe, (struct sockaddr *)&hint, sizeof(hint)) != 0)
        return -1;

    if (listen(tlv_transport_channel_new->tlv_transport_channel_pipe, 5) != 0)
        return -1;

    struct sockaddr_in tlv_transport_client;
    unsigned int tlv_transport_client_size = sizeof(tlv_transport_client);
    tlv_transport_channel_new->tlv_transport_channel_pipe = accept(tlv_transport_channel_new->tlv_transport_channel_pipe,
                                            (struct sockaddr *)&tlv_transport_client,
                                            &tlv_transport_client_size);
    #else
    WSADATA wsadata;

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
        return -1;

    tlv_transport_channel_new->tlv_transport_channel_pipe = socket(AF_INET, SOCK_STREAM, 0);

    if (tlv_transport_channel_new->tlv_transport_channel_pipe == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    SOCKADDR_IN hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(tlv_transport_channel_new->tlv_transport_channel_port);
    hint.sin_addr.s_addr = tlv_transport_channel_new->tlv_transport_channel_host;

    if (bind(tlv_transport_channel_new->tlv_transport_channel_pipe, (SOCKADDR *)&hint, sizeof(hint)) != 0) {
        closesocket(tlv_transport_channel_new->tlv_transport_channel_pipe);
        WSACleanup();
        return -1;
    }

    if (listen(tlv_transport_channel_new->tlv_transport_channel_pipe, 5) != 0)
    {
        closesocket(tlv_transport_channel_new->tlv_transport_channel_pipe);
        WSACleanup();
        return -1;
    }

    SOCKADDR_IN tlv_transport_client;
    int tlv_transport_client_size = sizeof(tlv_transport_client);
    tlv_transport_channel_new->tlv_transport_channel_pipe = accept(tlv_transport_channel_new->tlv_transport_channel_pipe,
                                                (SOCKADDR *)&tlv_transport_client,
                                                &tlv_transport_client_size);
    #endif

    return 0;
}

int tlv_transport_packet_split(tlv_transport_pkt_t tlv_transport_packet, char *** pool)
{
    int size = 1;
    char *data = strdup(tlv_transport_packet.tlv_transport_pkt_data);
    int len = strlen(data);

    char del = TLV_TRANSPORT_DEL;

    for (int i = 0; i < len; i++)
    {
        if (data[i] == del)
        {
            size++;
        }
    }

    char ** new_pool = malloc(size * sizeof(char *));

    int i = 0;
    int k = 0;

    new_pool[k++] = data;

    while (k < size)
    {
        if (data[i++] == del)
        {
            data[i-1] = '\0';
            new_pool[k++] = (data + i);
        }
    }

    *pool = new_pool;
    return size;
}

void tlv_transport_channel_send(tlv_transport_pkt_t tlv_transport_packet)
{
    tlv_transport_pkt_raw_t tlv_transport_pkt_new = tlv_transport_pkt_make_raw(tlv_transport_packet);

    send(tlv_transport_packet.tlv_transport_pkt_channel->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_scope, 2, 0);
    send(tlv_transport_packet.tlv_transport_pkt_channel->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_tag, 2, 0);
    send(tlv_transport_packet.tlv_transport_pkt_channel->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_status, 2, 0);
    send(tlv_transport_packet.tlv_transport_pkt_channel->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_size, 4, 0);

    if (tlv_transport_packet.tlv_transport_pkt_size > 0)
        send(tlv_transport_packet.tlv_transport_pkt_channel->tlv_transport_channel_pipe,
             tlv_transport_pkt_new.tlv_transport_pkt_data, tlv_transport_packet.tlv_transport_pkt_size, 0);
}

int tlv_transport_channel_send_file(tlv_transport_pkt_t tlv_transport_packet, tlv_transport_file_t tlv_transport_file_new)
{
    FILE *fp = fopen(tlv_transport_file_new.tlv_transport_file_from, "rb");

    if (fp != NULL)
    {
        int tlv_transport_bytes_read;

        tlv_transport_pkt_t tlv_transport_pkt_new = {
            .tlv_transport_pkt_channel = tlv_transport_packet.tlv_transport_pkt_channel,
            .tlv_transport_pkt_scope = tlv_transport_packet.tlv_transport_pkt_scope,
            .tlv_transport_pkt_tag = tlv_transport_packet.tlv_transport_pkt_tag,
            .tlv_transport_pkt_status = API_CALL_SUCCESS,
            .tlv_transport_pkt_size = 0,
        };

        tlv_transport_channel_send(tlv_transport_pkt_new);

        tlv_transport_pkt_new.tlv_transport_pkt_status = API_CALL_WAIT;
        tlv_transport_pkt_new.tlv_transport_pkt_data = malloc(TLV_TRANSPORT_CHUNK_SIZE);

        if (tlv_transport_pkt_new.tlv_transport_pkt_data != NULL)
        {
            while ((tlv_transport_bytes_read = fread(tlv_transport_pkt_new.tlv_transport_pkt_data, 1,
                    TLV_TRANSPORT_CHUNK_SIZE, fp)) > 0)
            {
                tlv_transport_pkt_new.tlv_transport_pkt_size = tlv_transport_bytes_read;
                tlv_transport_channel_send(tlv_transport_pkt_new);

                memset(tlv_transport_pkt_new.tlv_transport_pkt_data, 0, TLV_TRANSPORT_CHUNK_SIZE);
            }

            tlv_transport_pkt_free(tlv_transport_pkt_new);
            return 0;
        }

        fclose(fp);
    }

    return -1;
}

tlv_transport_pkt_t tlv_transport_channel_read(tlv_transport_channel_t *tlv_transport_channel_new,
                                               int append_zero_byte)
{
    tlv_transport_pkt_raw_t tlv_transport_pkt_new = {
        .tlv_transport_pkt_channel = tlv_transport_channel_new,
    };

    recv(tlv_transport_channel_new->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_scope, 2, 0);
    recv(tlv_transport_channel_new->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_tag, 2, 0);
    recv(tlv_transport_channel_new->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_status, 2, 0);
    recv(tlv_transport_channel_new->tlv_transport_channel_pipe,
         tlv_transport_pkt_new.tlv_transport_pkt_size, 4, 0);

    int size = UNPACK_INT(tlv_transport_pkt_new.tlv_transport_pkt_size);

    if (size > 0)
    {
        if (append_zero_byte)
        {
            tlv_transport_pkt_new.tlv_transport_pkt_data = malloc(size + 1);

            if (tlv_transport_pkt_new.tlv_transport_pkt_data != NULL)
            {
                recv(tlv_transport_channel_new->tlv_transport_channel_pipe,
                     tlv_transport_pkt_new.tlv_transport_pkt_data, size, 0);
                tlv_transport_pkt_new.tlv_transport_pkt_data[size] = 0;
            }
        } else
        {
            tlv_transport_pkt_new.tlv_transport_pkt_data = malloc(size);

            if (tlv_transport_pkt_new.tlv_transport_pkt_data != NULL)
            {
                recv(tlv_transport_channel_new->tlv_transport_channel_pipe,
                     tlv_transport_pkt_new.tlv_transport_pkt_data, size, 0);
            }
        }
    }

    return tlv_transport_pkt_make(tlv_transport_pkt_new);
}

int tlv_transport_channel_read_file(tlv_transport_pkt_t tlv_transport_packet,
                                     tlv_transport_file_t tlv_transport_file_new)
{
    FILE *fp = fopen(tlv_transport_file_new.tlv_transport_file_to, "wb");

    if (fp != NULL)
    {
        tlv_transport_pkt_t tlv_transport_pkt_new = {
            .tlv_transport_pkt_channel = tlv_transport_packet.tlv_transport_pkt_channel,
            .tlv_transport_pkt_scope = tlv_transport_packet.tlv_transport_pkt_scope,
            .tlv_transport_pkt_tag = tlv_transport_packet.tlv_transport_pkt_tag,
            .tlv_transport_pkt_status = API_CALL_SUCCESS,
            .tlv_transport_pkt_size = 0,
        };

        tlv_transport_channel_send(tlv_transport_pkt_new);
        tlv_transport_pkt_t tlv_transport_pkt_file = tlv_transport_channel_read(
            tlv_transport_pkt_new.tlv_transport_pkt_channel, 0);

        while (tlv_transport_pkt_file.tlv_transport_pkt_status == API_CALL_WAIT)
        {
            fwrite(tlv_transport_pkt_file.tlv_transport_pkt_data, sizeof(char),
                   tlv_transport_pkt_file.tlv_transport_pkt_size, fp);
            memset(tlv_transport_pkt_file.tlv_transport_pkt_data, 0,
                   tlv_transport_pkt_file.tlv_transport_pkt_size);
            tlv_transport_pkt_file = tlv_transport_channel_read(
                tlv_transport_pkt_new.tlv_transport_pkt_channel, 0);
        }

        tlv_transport_pkt_free(tlv_transport_pkt_file);

        fclose(fp);
        return 0;
    }

    return -1;
}

tlv_transport_pkt_t tlv_transport_pkt_make(tlv_transport_pkt_raw_t tlv_transport_packet)
{
    tlv_transport_pkt_t tlv_transport_pkt_new = {
        .tlv_transport_pkt_channel = tlv_transport_packet.tlv_transport_pkt_channel,
        .tlv_transport_pkt_scope = UNPACK_SHORT(tlv_transport_packet.tlv_transport_pkt_scope),
        .tlv_transport_pkt_tag = UNPACK_SHORT(tlv_transport_packet.tlv_transport_pkt_tag),
        .tlv_transport_pkt_status = UNPACK_SHORT(tlv_transport_packet.tlv_transport_pkt_status),
        .tlv_transport_pkt_size = UNPACK_INT(tlv_transport_packet.tlv_transport_pkt_size),
        .tlv_transport_pkt_data = tlv_transport_packet.tlv_transport_pkt_data,
    };

    return tlv_transport_pkt_new;
}

tlv_transport_pkt_raw_t tlv_transport_pkt_make_raw(tlv_transport_pkt_t tlv_transport_packet)
{
    tlv_transport_pkt_raw_t tlv_transport_pkt_new = {
        .tlv_transport_pkt_channel = tlv_transport_packet.tlv_transport_pkt_channel,
    };

    PACK_SHORT(tlv_transport_packet.tlv_transport_pkt_scope, tlv_transport_pkt_new.tlv_transport_pkt_scope);
    PACK_SHORT(tlv_transport_packet.tlv_transport_pkt_tag, tlv_transport_pkt_new.tlv_transport_pkt_tag);
    PACK_SHORT(tlv_transport_packet.tlv_transport_pkt_status, tlv_transport_pkt_new.tlv_transport_pkt_status);
    PACK_INT(tlv_transport_packet.tlv_transport_pkt_size, tlv_transport_pkt_new.tlv_transport_pkt_size);
    tlv_transport_pkt_new.tlv_transport_pkt_data = tlv_transport_packet.tlv_transport_pkt_data;

    return tlv_transport_pkt_new;
}

void tlv_transport_pkt_free(tlv_transport_pkt_t tlv_transport_packet)
{
    free(tlv_transport_packet.tlv_transport_pkt_data);
}

void tlv_transport_channel_close(tlv_transport_channel_t *tlv_transport_channel_new)
{
    #ifndef _WIN32
    close(tlv_transport_channel_new->tlv_transport_channel_pipe);
    #else
    closesocket(tlv_transport_channel_new->tlv_transport_channel_pipe);
    #endif
}
