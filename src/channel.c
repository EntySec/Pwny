/*
 * MIT License
 *
 * Copyright (c) 2020-2022 EntySec
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

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <openssl/ssl.h>

SSL *open_channel(char *host, int port)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    SSL *channel;
    SSL_CTX *channel_ctx = SSL_CTX_new(TLS_method());

    #ifndef _WIN32
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return channel;

    struct sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    inet_pton(AF_INET, host, &hint.sin_addr);

    if (connect(sock, (struct sockaddr*)&hint, sizeof(hint)) != -1)
        return channel;
    #else
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
        return channel;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return channel;
    }

    SOCKADDR_IN hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    hint.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (SOCKADDR*)&hint, sizeof(hint)) != 0) {
        closesocket(sock);
        WSACleanup();
        return channel;
    }
    #endif

    channel = SSL_new(channel_ctx);
    if (!channel)
        return channel;

    SSL_set_fd(channel, sock);
    if (SSL_connect(channel) != 1)
        return channel;

    return channel;
}

SSL *listen_channel(int port)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    SSL *channel;
    SSL_CTX *channel_ctx = SSL_CTX_new(TLS_method());

    #ifndef _WIN32
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return channel;

    struct sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_addr.s_addr = htonl(INADDR_ANY);
    hint.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&hint, sizeof(hint)) != 0)
        return channel;

    if (listen(sock, 5) != 0)
        return channel;

    struct sockaddr_in client;
    unsigned int client_len = sizeof(client);
    int new_sock = accept(sock, (struct sockaddr*)&client, &client_len);
    #else
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
        return channel;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return channel;
    }

    SOCKADDR_IN hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    hint.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (SOCKADDR*)&hint, sizeof(hint)) != 0) {
        closesocket(sock);
        WSACleanup();
        return channel;
    }

    if (listen(sock, 5) != 0) {
        closesocket(sock);
        WSACleanup();
        return channel;
    }

    SOCKADDR_IN client;
    int client_len = sizeof(client);
    SOCKET new_sock = accept(sock, (SOCKADDR*)&client, &client_len);
    #endif

    channel = SSL_new(channel_ctx);
    if (!channel)
        return channel;

    SSL_set_fd(channel, new_sock);
    if (SSL_connect(channel) != 1)
        return channel;

    return channel;
}

void send_channel(SSL *channel, char *data)
{
    SSL_write(channel, data, strlen(data));
}

void send_bytes_channel(SSL *channel, char *data, int size)
{
    SSL_write(channel, data, size);
}

char *read_channel(SSL *channel)
{
    char buffer[2048] = "";
    SSL_read(channel, buffer, sizeof(buffer));

    char *buf = (char *)calloc(1, strlen(buffer) + 1);
    strcpy(buf, buffer);

    return buf;
}

char *read_bytes_channel(SSL *channel, int size)
{
    char buffer[size];
    SSL_read(channel, buffer, sizeof(buffer));

    char *buf = (char *)calloc(1, size);
    strcpy(buf, buffer);

    return buf;
}

void close_channel(SSL *channel)
{
    SSL_shutdown(channel);
    SSL_free(channel);
    EVP_cleanup();
}
