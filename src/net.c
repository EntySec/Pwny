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
#include "net.h"
#include "json.h"

#include "uthash/uthash.h"

int net_json_parse_host(json_object_t *json_object_new)
{
    char *o1 = find_json(json_object_new, "o1");
    char *o2 = find_json(json_object_new, "o2");
    char *o3 = find_json(json_object_new, "o3");
    char *o4 = find_json(json_object_new, "o4");

    if (o1 == NULL || o2 == NULL || o3 == NULL || o4 == NULL)
        return -1;

    return PACK_IPV4(atoi(o1), atoi(o2), atoi(o3), atoi(o4));
}

int net_json_parse_type(json_object_t *json_object_new)
{
    char *t = find_json(json_object_new, "t");

    if (t == NULL)
        return -1;

    return atoi(t);
}

int net_json_parse_port(json_object_t *json_object_new)
{
    char *p = find_json(json_object_new, "p");

    if (p == NULL)
        return -1;

    return atoi(p);
}

char *net_local_hostname()
{
    char *buffer = (char *)malloc(MAX_HOSTNAME_BUF + 1);
    gethostname(buffer, MAX_HOSTNAME_BUF + 1);
    return buffer;
}

void net_c2_add(net_c2_t **net_c2_data, int net_c2_id, int net_c2_host,
                int net_c2_port, char *net_c2_name, int net_c2_bind)
{
    net_c2_t *net_c2_new = calloc(1, sizeof(*net_c2_new));

    if (net_c2_new != NULL)
    {
        net_c2_new->net_c2_id = net_c2_id;
        net_c2_new->net_c2_host = net_c2_host;
        net_c2_new->net_c2_port = net_c2_port;
        net_c2_new->net_c2_name = net_c2_name;
        net_c2_new->net_c2_bind = net_c2_bind;

        net_c2_t *net_c2_data_new;
        HASH_FIND_INT(*net_c2_data, &net_c2_id, net_c2_data_new);

        if (net_c2_data_new == NULL)
        {
            HASH_ADD_INT(*net_c2_data, net_c2_id, net_c2_new);
            log_debug("* Added net C2 entry (%d) - (%s)\n", net_c2_id, net_c2_name);
        }
    }
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
