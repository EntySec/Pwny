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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>

#include <ev.h>
#include <log.h>

#include <net_server.h>
#include <net_client.h>

net_server_t *net_server_create(void)
{
    net_server_t *net_server;

    net_server = calloc(1, sizeof(*net_server));

    if (net_server == NULL)
    {
        return NULL;
    }

    net_server->listener = 0;
    return net_server;
}

void net_on_accept(struct ev_loop *loop, struct ev_io *w, int revents)
{
    log_debug("* Accept event initialized\n");
    int sock;
    socklen_t length;

    struct sockaddr_storage sockaddr;

    net_t *net;
    net_server_t *net_server;

    net_server = w->data;
    length = sizeof(sockaddr);

    sock = accept(net_server->listener, (struct sockaddr *)&sockaddr, &length);

    if (sock < 0)
    {
        log_debug("* Failed to accept connection!\n");
        return;
    }

    if (sock > FD_SETSIZE)
    {
        close(sock);
        return;
    }

    net = net_create();

    if (net == NULL)
    {
        return;
    }

    net_set_links(net, net_server->read_link,
                  net_server->write_link, net_server->event_link,
                  net_server->link_data);
    net_setup(net, net_server->loop);
    net_add_sock(net, sock, net_server->proto);

    log_debug("* Accepted connection\n");

    if (net_server->event_link)
    {
        net_server->event_link(NET_SERVER_CLIENT, net);
        return;
    }

    net_free(net);
}

int net_server_start(net_server_t *net_server, enum NET_PROTO proto,
                     char *host, int port)
{
    char ipv6_addr[INET6_ADDRSTRLEN];
    int is_ipv6;
    int reuseaddr;

    struct addrinfo *resolved;
    struct addrinfo hints;

    struct sockaddr_in6 *ipv6;
    struct sockaddr_in6 sockaddr6;
    struct sockaddr_un sockaddr;

    is_ipv6 = 0;
    reuseaddr = 1;

    if (proto == NET_PROTO_UNIX)
    {
        memset(&sockaddr, 0, sizeof(sockaddr));
        sockaddr.sun_family = AF_UNIX;
        strcpy(sockaddr.sun_path, host);
        sockaddr.sun_path[0] = 0;

        net_server->listener = socket(AF_UNIX, SOCK_STREAM, 0);
        if (net_server->listener < 0)
        {
            goto fail;
        }
        net_nonblock_sock(net_server->listener);
    }
    else
    {
        sockaddr6.sin6_family = AF_INET6;
        sockaddr6.sin6_port = htons(port);

        if (host == NULL || strlen(host) == 0)
        {
            sockaddr6.sin6_addr = in6addr_any;
        }
        else
        {
            resolved = NULL;
            hints.ai_family = AF_UNSPEC;
            hints.ai_flags = AI_NUMERICHOST;

            if (getaddrinfo(host, NULL, &hints, &resolved) != 0)
            {
                goto fail;
            }

            if (resolved->ai_family == AF_INET)
            {
                snprintf(ipv6_addr, INET6_ADDRSTRLEN, "::ffff:%s", host);
                if (inet_pton(AF_INET6, ipv6_addr, &sockaddr6.sin6_addr) <= 0)
                {
                    sockaddr6.sin6_addr = in6addr_any;
                }
            }
            else if (resolved->ai_family == AF_INET6)
            {
                is_ipv6 = 1;
                ipv6 = (struct sockaddr_in6 *)resolved->ai_addr;
                memcpy(&sockaddr6.sin6_addr, &ipv6->sin6_addr, resolved->ai_addrlen);
            }
            else
            {
                freeaddrinfo(resolved);
                goto fail;
            }
        }

        net_server->listener = socket(AF_INET6, SOCK_STREAM, 0);
        if (net_server->listener < 0)
        {
            goto fail;
        }

        net_nonblock_sock(net_server->listener);
        setsockopt(net_server->listener, SOL_SOCKET, SO_REUSEADDR, (void *)&reuseaddr, sizeof(reuseaddr));

#ifdef IPV6_V6ONLY
        setsockopt(net_server->listener, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&is_ipv6, sizeof(is_ipv6));
#endif
    }

    if (proto == NET_PROTO_UNIX)
    {
        if (bind(net_server->listener, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0)
        {
            goto fail;
        }
    }
    else
    {
        if (bind(net_server->listener, (struct sockaddr *)&sockaddr6, sizeof(sockaddr6)) < 0)
        {
            goto fail;
        }
    }

    if (listen(net_server->listener, 16) < 0)
    {
        goto fail;
    }

    ev_io_init(&net_server->event_io, net_on_accept, net_server->listener, EV_READ);
    net_server->event_io.data = net_server;
    ev_io_start(net_server->loop, &net_server->event_io);

    log_debug("* Started server (%d)\n", net_server->listener);
    return 0;

fail:
    log_debug("* Failed to start server\n");
    close(net_server->listener);
    net_server->listener = 0;
    return -1;
}

void net_server_setup(net_server_t *net_server, struct ev_loop *loop)
{
    net_server->loop = loop;
}

void net_server_set_links(net_server_t *net_server,
                          link_t read_link,
                          link_t write_link,
                          link_event_t event_link,
                          void *data)
{
    net_server->read_link = read_link;
    net_server->write_link = write_link;
    net_server->event_link = event_link;
    net_server->link_data = data != NULL ? data : net_server;
}

void net_server_stop(net_server_t *net_server)
{
    if (net_server->listener == 0)
    {
        return;
    }

    ev_io_stop(net_server->loop, &net_server->event_io);
    close(net_server->listener);
    net_server->listener = 0;
}

void net_server_free(net_server_t *net_server)
{
    free(net_server);
}