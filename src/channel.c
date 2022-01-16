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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int open_channel(char *host, int port)
{
    int channel = socket(AF_INET, SOCK_STREAM, 0);
    if (channel == -1)
        return -1;

    struct sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    inet_pton(AF_INET, host, &hint.sin_addr);

    if (connect(channel, (struct sockaddr*)&hint, sizeof(hint)) == -1)
        return -1;

    return channel;
}

int listen_channel(int port)
{
    int channel = socket(AF_INET, SOCK_STREAM, 0);
    if (channel == -1)
        return -1;

    struct sockaddr_in hint;
    hint.sin_family = AF_INET;
    hint.sin_addr.s_addr = htonl(INADDR_ANY);
    hint.sin_port = htons(port);
   
    if (bind(channel, (struct sockaddr*)&hint, sizeof(hint)) != 0)
        return -1;
   
    if (listen(channel, 5) != 0)
        return -1;

    struct sockaddr_in client;

    unsigned int client_len = sizeof(client);
    int new_channel = accept(channel, (struct sockaddr*)&client, &client_len);

    return new_channel;
}

void send_channel(int channel, char *data)
{
    send(channel, data, (int)strlen(data), 0);
}

char *read_channel(int channel)
{
    char buffer[2048] = "";
    recv(channel, buffer, sizeof(buffer), 0);

    char *buf = (char *)calloc(1, strlen(buffer) + 1);
    strcpy(buf, buffer);

    return buf;
}

void close_channel(int channel)
{
    close(channel);
}
