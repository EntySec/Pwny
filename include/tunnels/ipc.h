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

#ifndef _IPC_H_
#define _IPC_H_

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

static void ipc_tunnel_write(tunnel_t *tunnel, queue_t *egress)
{
    size_t size;
    net_t *net;
    void *buffer;

    net = tunnel->data;

    if (egress->bytes <= 0)
    {
        return;
    }

    while ((size = queue_remove_all(egress, &buffer)) > 0)
    {
        log_debug("* Writing bytes to FILE (%d) - (%d)\n", net->io->pipe[1], size);
        write(net->io->pipe[1], buffer, size);
        free(buffer);
    }

    free(buffer);
}

static void ipc_tunnel_read(void *data)
{
    size_t bytes;
    net_t *net;
    tunnel_t *tunnel;

    tunnel = data;
    net = tunnel->data;

    log_debug("* Read IPC event initialized (%d)\n", net->io->pipe[0]);

    if ((bytes = queue_from_fd(tunnel->ingress, net->io->pipe[0])) > 0)
    {
        log_debug("* Read bytes via IPC (%d) - (%d)\n", net->io->pipe[0], bytes);

        if (tunnel->read_link)
        {
            tunnel->read_link(tunnel->link_data);
        }
    }
}

int ipc_tunnel_start(tunnel_t *tunnel)
{
    net_t *net;

    net = tunnel->data;
    net_start(net);

    return 0;
}

int ipc_tunnel_init(tunnel_t *tunnel)
{
    net_t *net;

    net = net_create();

    if (net == NULL)
    {
        return -1;
    }

    net_add_pipes(net, STDIN_FILENO, STDOUT_FILENO);
    net_set_links(net, ipc_tunnel_read,
                  NULL, NULL, tunnel);
    net_setup(net, tunnel->loop);

    tunnel->data = net;

    tunnel->ingress = net->io->ingress;
    tunnel->egress = net->io->egress;
    tunnel->active = 1;

    return 0;
}

void ipc_tunnel_exit(tunnel_t *tunnel)
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

void register_ipc_tunnels(tunnels_t **tunnels)
{
    tunnel_callbacks_t callbacks;

    callbacks.init_cb = ipc_tunnel_init;
    callbacks.start_cb = ipc_tunnel_start;
    callbacks.write_cb = ipc_tunnel_write;
    callbacks.exit_cb = ipc_tunnel_exit;

    register_tunnel(tunnels, "ipc", callbacks);
}

#endif
