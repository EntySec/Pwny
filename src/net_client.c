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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ev.h>
#include <eio.h>

#include <log.h>
#include <net_client.h>
#include <io.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

net_t *net_create(void)
{
    net_t *net;

    net = calloc(1, sizeof(*net));

    if (net == NULL)
    {
        return NULL;
    }

    net->io = io_create();
    net->status = NET_STATUS_CLOSED;
    net->delay = 1.0;

    if (net->io == NULL)
    {
        free(net);
        return NULL;
    }

    return net;
}

int net_nonblock_sock(int sock)
{
#ifdef IS_WINDOWS
    unsigned long non_block;

    non_block = 1;

    if (ioctlsocket(sock, FIONBIO, &non_block) == SOCKET_ERROR)
    {
        return -1;
    }
#else
    int flags;

    if ((flags = fcntl(sock, F_GETFL, NULL)) < 0)
    {
        return -1;
    }

    if (!(flags & O_NONBLOCK))
    {
        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
        {
            return -1;
        }
    }
#endif

    return 0;
}

static void log_addrinfo(char *message, struct addrinfo *addrinfo)
{
    char *proto;
    char host[INET6_ADDRSTRLEN];
    struct sockaddr_in *hint;
    struct sockaddr_in6 *hint6;
    uint16_t port;

    proto = addrinfo->ai_protocol == IPPROTO_UDP ? "udp" : "tcp";
    memset(host, '\0', INET6_ADDRSTRLEN);
    port = 0;

    if (addrinfo->ai_family == AF_INET)
    {
        hint = (struct sockaddr_in *)addrinfo->ai_addr;
        port = ntohs(hint->sin_port);
        inet_ntop(AF_INET, &hint->sin_addr, host, INET6_ADDRSTRLEN);
    }
    else
    {
        hint6 = (struct sockaddr_in6 *)addrinfo->ai_addr;
        port = ntohs(hint6->sin6_port);
        inet_ntop(AF_INET6, &hint6->sin6_addr, host, INET6_ADDRSTRLEN);
    }

    if (strchr(host, ':') != NULL)
    {
        log_debug("%s (%s://[%s]:%d)\n", message, proto, host, port);
        return;
    }

    log_debug("%s (%s://%s:%d)\n", message, proto, host, port);
}

static void net_resolve(struct eio_req *request)
{
    net_t *net;
    char port[6];
    struct addrinfo hint;

    net = request->data;

    if (net->dest)
    {
        return;
    }

    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_CANONNAME;

    if (net->proto == NET_PROTO_UDP)
    {
        hint.ai_socktype = SOCK_DGRAM;
        hint.ai_protocol = IPPROTO_UDP;
    }
    else
    {
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_protocol = IPPROTO_TCP;
    }

    log_debug("* Resolving URI (%s)\n", net->uri);

    net->status = NET_STATUS_RESOLVE;
    request->result = getaddrinfo(net->host, net->port, &hint, &net->dest);

    if ((net->src_addr || net->src_port) && net->src == NULL)
    {
        if (net->src_port > 0)
        {
            snprintf(port, sizeof(port), "%u", net->src_port);
            getaddrinfo(net->src_addr, port, &hint, &net->src);
        }
        else
        {
            getaddrinfo(net->src_addr, NULL, &hint, &net->src);
        }
    }
}

static void net_on_connect(struct ev_loop *loop, struct ev_io *w, int events)
{
    int status;
    socklen_t len;
    net_t *net;

    net = w->data;

    ev_io_stop(net->loop, &net->event_io);

    len = sizeof(status);
    getsockopt(net->io->pipe[0], SOL_SOCKET, SO_ERROR, &status, &len);

    if (status != 0)
    {
        log_debug("* Not connected (%s)\n", net->uri);
        net->status = NET_STATUS_CLOSED;

        if (net->event_link)
        {
            net->event_link(NET_STATUS_CLOSED, net->link_data);
        }

        return;
    }

    log_debug("* Connected to (%s)\n", net->uri);

    net->status = NET_STATUS_OPEN;
    io_start(net->io);

    if (net->event_link)
    {
        net->event_link(NET_STATUS_OPEN, net->link_data);
    }
}

static int net_on_resolve(struct eio_req *request)
{
    net_t *net;
    int sock;
    int status;
    struct sockaddr *udp;
    struct sockaddr_in hint;
    struct addrinfo *addrinfo;
    socklen_t udp_length;

    net = request->data;
    addrinfo = net->dest;

    if (request->result != 0)
    {
        log_debug("* Failed to resolve URI (%s)\n", net->uri);
        net->status = NET_STATUS_CLOSED;
        return -1;
    }

    log_addrinfo("* Connecting to an endpoint", addrinfo);

    net->status = NET_STATUS_CONNECTING;
    sock = socket(addrinfo->ai_family, addrinfo->ai_socktype,
                  addrinfo->ai_protocol);
    if (sock < 0)
    {
        net->status = NET_STATUS_CLOSED;
        return -1;
    }

    net_nonblock_sock(sock);

    if (addrinfo->ai_protocol == IPPROTO_UDP)
    {
        hint.sin_family = AF_INET;
        hint.sin_port = htons(0);
        hint.sin_addr.s_addr = INADDR_ANY;

        if (net->src)
        {
            udp = net->src->ai_addr;
            udp_length = net->src->ai_addrlen;
        }
        else
        {
            udp = (struct sockaddr *)(&hint);
            udp_length = sizeof hint;
        }

        if (bind(sock, udp, udp_length) != 0)
        {
            log_debug("* Failed to bind (%s)\n", strerror(errno));
            return -1;
        }
    }
    else
    {
        if (net->src)
        {
            if (bind(sock, net->src->ai_addr, net->src->ai_addrlen) != 0)
            {
                log_debug("* Failed to bind (%s)\n", strerror(errno));
                return -1;
            }
        }
    }

    status = connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen);

    if (status == 0 || errno == EINPROGRESS || errno == EWOULDBLOCK)
    {
        io_add_pipes(net->io, sock, sock);

        ev_io_init(&net->event_io, net_on_connect, sock, EV_WRITE);
        net->event_io.data = net;
        ev_io_start(net->loop, &net->event_io);

        return 0;
    }

    close(sock);
    return -1;
}

void net_timer(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    net_t *net;
    net = w->data;

    if (net->status != NET_STATUS_CLOSED)
    {
        return;
    }

    eio_custom(net_resolve, 0, net_on_resolve, net);
}

void net_set_delay(net_t *net, float delay)
{
    net->delay = delay;
}

void net_start(net_t *net)
{
    if (net->proto == NET_PROTO_UDP || net->proto == NET_PROTO_TCP)
    {
        ev_timer_stop(net->loop, &net->timer);
        ev_timer_init(&net->timer, net_timer, 0, net->delay);
        net->timer.data = net;
        ev_timer_start(net->loop, &net->timer);
    }
}

static void net_read_link(void *data)
{
    net_t *net;

    net = data;

    if (net->read_link)
    {
        net->read_link(net->link_data);
    }
}

static void net_event_link(int event, void *data)
{
    net_t *net;

    net = data;

    net->status = event;
    if (net->event_link)
    {
        net->event_link(event, net->link_data);
    }
}

static void net_write_link(void *data)
{
    net_t *net;

    if (net->write_link)
    {
        net->write_link(net->link_data);
    }
}

void net_setup(net_t *net, struct ev_loop *loop)
{
    net->loop = loop;
    io_set_links(net->io, net_read_link,
                 net_write_link, net_event_link,
                 net);
    io_setup(net->io, net->loop);
}

void net_set_src(net_t *net, char *addr, uint16_t port)
{
    if (net->src_addr)
    {
        free(net->src_addr);
        net->src_addr = NULL;
    }

    if (addr && strcmp(addr, "0.0.0.0"))
    {
        net->src_addr = strdup(addr);
    }

    if (net->src)
    {
        freeaddrinfo(net->src);
        net->src = NULL;
    }

    net->src_port = port;
}

void net_add_pipes(net_t *net, int in_pipe, int out_pipe)
{
    log_debug("* Adding busy pipes (in: %d, out: %d) to net\n",
              in_pipe, out_pipe);

    io_add_pipes(net->io, in_pipe, out_pipe);

    net->proto = NET_PROTO_FILE;
    net->status = NET_STATUS_OPEN;
}

int net_add_sock(net_t *net, int sock, int proto)
{
    char port[7];
    struct sockaddr_in *hint;
    struct sockaddr_in6 *hint6;
    struct sockaddr_storage addr;
    socklen_t addr_len;

    log_debug("* Adding busy socket (%d) to net\n", sock);

    getpeername(sock, (struct sockaddr *)&addr, &addr_len);
    net->host = calloc(1, INET6_ADDRSTRLEN);

    if (net->host == NULL)
    {
        log_debug("* Failed to allocate space for host\n");
        return -1;
    }

    if (addr.ss_family == AF_INET)
    {
        hint = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &hint->sin_addr, net->host, INET6_ADDRSTRLEN);
        snprintf(port, sizeof(port), "%d", ntohs(hint->sin_port));
    }
    else
    {
        hint6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET, &hint6->sin6_addr, net->host, INET6_ADDRSTRLEN);
        snprintf(port, sizeof(port), "%d", ntohs(hint6->sin6_port));
    }

    net->port = strdup(port);
    net->proto = proto;
    net->status = NET_STATUS_OPEN;

    io_add_pipes(net->io, sock, sock);
    return 0;
}

int net_add_uri(net_t *net, char *uri)
{
    char *port;
    char *host;
    char *proto;
    char *temp_uri;
    char *ipv6_end;

    temp_uri = strdup(uri);
    host = strstr(temp_uri, "://");
    net->uri = strdup(uri);

    if (temp_uri == NULL || net->uri == NULL)
    {
        log_debug("* Failed to obtain URI (%s)\n", uri);
        goto fail;
    }

    if (host == NULL)
    {
        proto = "tcp";
        host = temp_uri;
    }
    else
    {
        host[0] = '\0';
        proto = temp_uri;
        host += 3;
    }

    if (proto == NULL || host == NULL)
    {
        log_debug("* Failed to add URI (%s)\n", uri);
        goto fail;
    }

    if (*host == '[')
    {
        host++;
        ipv6_end = host;

        while (*ipv6_end != 0 && *ipv6_end != ']')
        {
            ipv6_end++;
        }
        if (*ipv6_end == ']')
        {
            *ipv6_end = '\0';
        }
        else
        {
            log_debug("* Invalid IPv6 address (%s)\n", uri);
            goto fail;
        }

        port = ipv6_end + 1;

        if (*port == ':' && port[1] != '\0')
        {
            port++;
        }
        else
        {
            port = NULL;
        }
    }
    else
    {
        port = strstr(host, ":");

        if (port)
        {
            port[0] = '\0';
            port++;
        }
    }

    net->host = strdup(host);
    if (strcmp(proto, "tcp") == 0)
    {
        net->proto = NET_PROTO_TCP;
    }
    else if (strcmp(proto, "udp") == 0)
    {
        net->proto = NET_PROTO_UDP;
    }

    if (port)
    {
        net->port = strdup(port);
    }
    else
    {
        log_debug("* Port is not defined for protocol (%s)\n", proto);
        goto fail;
    }

    free(temp_uri);
    return 0;

fail:
    return -1;
}

void net_set_links(net_t *net,
                   link_t read_link,
                   link_t write_link,
                   link_event_t event_link,
                   void *data)
{
    net->read_link = read_link;
    net->write_link = write_link;
    net->event_link = event_link;
    net->link_data = data != NULL ? data : net;
}

void net_stop(net_t *net)
{
    if (net->io)
    {
        io_stop(net->io);
        net->status = NET_STATUS_CLOSED;
    }

    if (net->dest)
    {
        freeaddrinfo(net->dest);
        net->dest = NULL;
    }

    if (net->src)
    {
        freeaddrinfo(net->src);
        net->src = NULL;
    }
}

void net_stop_timer(net_t *net)
{
    ev_timer_stop(net->loop, &net->timer);
}

void net_free(net_t *net)
{
    if (net->host)
    {
        free(net->host);
    }

    if (net->port)
    {
        free(net->port);
    }

    if (net->uri)
    {
        free(net->uri);
    }

    io_free(net->io);
    free(net);
}
