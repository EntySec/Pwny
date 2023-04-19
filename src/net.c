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

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include "log.h"
#include "tlv.h"
#include "console.h"
#include "net.h"

#include "uthash/uthash.h"

char *net_local_hostname()
{
    char *buffer = (char *)malloc(MAX_HOSTNAME_BUF + 1);
    gethostname(buffer, MAX_HOSTNAME_BUF + 1);
    return buffer;
}

void net_c2_add(net_c2_t **net_c2_data, int net_c2_id, int net_c2_fd, char *net_c2_name)
{
    net_c2_t *net_c2_new = calloc(1, sizeof(*net_c2_new));

    if (net_c2_new != NULL)
    {
        net_c2_new->net_c2_id = net_c2_id;
        net_c2_new->net_c2_fd = net_c2_fd;
        net_c2_new->net_c2_name = net_c2_name;

        net_c2_t *net_c2_data_new;
        HASH_FIND_INT(*net_c2_data, &net_c2_id, net_c2_data_new);

        if (net_c2_data_new == NULL)
        {
            HASH_ADD_INT(*net_c2_data, net_c2_id, net_c2_new);
            log_debug("* Added net C2 entry (%d) - (%s)\n", net_c2_id, net_c2_name);
        }
    }
}

void net_c2_init(net_c2_t **net_c2_data)
{
    net_c2_t *c2;

    for (c2 = net_c2_data; c2 != NULL; c2 = c2->hh.next)
    {
        tlv_transport_channel_t tlv_transport_channel_new;
        tlv_transport_channel_new.tlv_transport_channel_pipe = c2->net_c2_fd;

        tlv_console_loop(&tlv_transport_channel_new);
        tlv_transport_channel_close(&tlv_transport_channel_new);

        HASH_DEL(net_c2_data);
        free(c2);
    }
}

void net_c2_free(net_c2_t **net_c2_data)
{
    free(net_c2_data);
}

static void com(net_data_t net_data_new)
{
    char buf[1024 * 4];
    int r, i, j;

    r = read(net_data_new.net_data_src, buf, 1024 * 4);

    while (r > 0) {
        i = 0;

        while (i < r) {
            j = write(net_data_new.net_data_dst, buf + i, r - i);

            if (j == -1) {
                return;
            }

            i += j;
        }

        r = read(net_data_new.net_data_src, buf, 1024 * 4);
    }

    if (r == -1) {
        return;
    }

    #ifndef WINDOWS
    close(net_data_new.net_data_src);
    close(net_data_new.net_data_dst);
    #else
    closesocket(net_data_new.net_data_src);
    closesocket(net_data_new.net_data_dst);
    #endif
}

int net_forward_traffic(net_forwarder_t *net_forwarder_new)
{
    net_forwarder_new = NULL; // hax!
    return 1;
}
