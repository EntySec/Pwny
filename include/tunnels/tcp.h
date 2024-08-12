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

#ifndef _TCP_H_
#define _TCP_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <log.h>
#include <tunnel.h>
#include <net_client.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

static void tcp_tunnel_write(tunnel_t *tunnel, queue_t *egress)
{
    net_t *net;
    size_t size;
    ssize_t stat;
    ssize_t offset;
    void *buffer;

    buffer = NULL;
    offset = 0;

    net = tunnel->data;

    if (egress->bytes <= 0)
    {
        return;
    }

    while ((size = queue_remove_all(egress, &buffer)) > 0)
    {
        log_debug("* Writing bytes to TCP (%d) - (%d)\n", net->io->pipe[1], size);

        do
        {
            stat = send(net->io->pipe[1], buffer + offset, size - offset, 0);

            if (stat > 0)
            {
                offset += stat;
            }
        }
        while (stat > 0);

        free(buffer);
    }

    free(buffer);
}

static void tcp_tunnel_event(int event, void *data)
{
    tunnel_t *tunnel;

    tunnel = data;

    if (tunnel->event_link)
    {
        tunnel->event_link(event, tunnel->link_data);
    }
}

static void tcp_tunnel_read(void *data)
{
    net_t *net;
    tunnel_t *tunnel;

    int error;
    size_t bytes;
    ssize_t stat;
    char buffer[NET_QUEUE_SIZE];

    tunnel = data;
    net = tunnel->data;

    log_debug("* Read TCP event initialized (%d)\n", net->io->pipe[0]);

    while ((stat = read(net->io->pipe[0], buffer, sizeof(buffer))) > 0)
    {
        log_debug("* Read bytes via TCP (%d) - (%d)\n", net->io->pipe[0], stat);
        queue_add_raw(tunnel->ingress, buffer, stat);
        bytes += stat;
    }

    error = errno;

    if (bytes > 0 && tunnel->read_link)
    {
        tunnel->read_link(tunnel->link_data);
    }

    if (stat == 0)
    {
        log_debug("* Read TCP connection shutdown (%d)\n", net->io->pipe[0]);
        net_stop(net);
    }
    else if (stat == -1 && error != EAGAIN && error != EINPROGRESS && error != EWOULDBLOCK)
    {
        log_debug("* Read TCP connection terminated (%d)\n", net->io->pipe[0]);
        net_stop(net);
    }
}

int tcp_tunnel_start(tunnel_t *tunnel)
{
    net_t *net;

    net = tunnel->data;

    net_set_delay(net, tunnel->delay);
    net_start(net);

    return 0;
}

int tcp_tunnel_init(tunnel_t *tunnel)
{
    net_t *net;

    net = net_create();

    if (net == NULL)
    {
        return -1;
    }

    net_add_uri(net, tunnel->uri);
    net_set_links(net, tcp_tunnel_read,
                  NULL, tcp_tunnel_event, tunnel);
    net_setup(net, tunnel->loop);

    tunnel->data = net;
    tunnel->active = 1;

    tunnel->ingress = net->io->ingress;
    tunnel->egress = net->io->egress;

    return 0;
}

void tcp_tunnel_exit(tunnel_t *tunnel)
{
    net_t *net;

    if (!tunnel->active)
    {
        return;
    }

    net = tunnel->data;

    net_stop(net);
    net_stop_timer(net);
    net_free(net);

    tunnel->active = 0;
}

int sock_tunnel_init(tunnel_t *tunnel)
{
    net_t *net;
    char *uri;
    int fd;

    net = net_create();

    if (net == NULL)
    {
        return -1;
    }

    uri = strdup(tunnel->uri);
    fd = strtol(strstr(uri, "://") + 3, NULL, 10);

    net_add_sock(net, fd, NET_PROTO_TCP);
    net_set_links(net, tcp_tunnel_read,
                  NULL, tcp_tunnel_event, tunnel);
    net_setup(net, tunnel->loop);

    tunnel->data = net;
    tunnel->active = 1;

    tunnel->ingress = net->io->ingress;
    tunnel->egress = net->io->egress;

    free(uri);
    return 0;
}

void sock_tunnel_exit(tunnel_t *tunnel)
{
    net_t *net;

    if (!tunnel->active)
    {
        return;
    }

    net = tunnel->data;

    net_stop(net);
    net_free(net);

    tunnel->active = 0;
}

void register_tcp_tunnels(tunnels_t **tunnels)
{
    tunnel_callbacks_t tcp_callbacks;

    tcp_callbacks.init_cb = tcp_tunnel_init;
    tcp_callbacks.start_cb = tcp_tunnel_start;
    tcp_callbacks.write_cb = tcp_tunnel_write;
    tcp_callbacks.exit_cb = tcp_tunnel_exit;

    sock_callbacks.init_cb = sock_tunnel_init;
    sock_callbacks.start_cb = tcp_tunnel_start;
    sock_callbacks.write_cb = tcp_tunnel_write;
    sock_callbacks.exit_cb = sock_tunnel_exit;

    register_tunnel(tunnels, "tcp", tcp_callbacks);
    register_tunnel(tunnels, "sock", sock_callbacks);
}

#endif
