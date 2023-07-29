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

#include <unistd.h>
#include <pthread.h>

#ifndef WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <node.h>
#include <log.h>

/*
 * Thread for traffic forwarder between nodes.
 */

static void *node_thread(void *data)
{
    nodes_t *node = (nodes_t *)data;

    int sock_from = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_from == -1)
        return NULL;

    struct sockaddr_in addr_from = {
        .sin_family = AF_INET,
        .sin_port = htons(node->src_port),
        .sin_addr.s_addr = node->src_host
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
            .sin_port = htons(node->dst_port),
            .sin_addr.s_addr = node->dst_host
        };

        if (connect(new_sock, (struct sockaddr *)&addr_new, sizeof(addr_new)) == -1)
        {
            close(sock_to);
            close(new_sock);
        }

        log_debug("* New connection: %s:%d -> %s:%d\n", inet_ntoa(addr_to.sin_addr),
                  ntohs(addr_to.sin_port), inet_ntoa(addr_from.sin_addr),
                  node->src_port);

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
                char buffer[NODE_CHUNK];
                ssize_t bytes_read = recv(new_sock, buffer, sizeof(buffer), 0);

                if (bytes_read <= 0)
                    break;

                send(sock_to, buffer, bytes_read, 0);
            }
        }

        log_debug("* Connection closed: %s:%d -> %s:%d\n", inet_ntoa(addr_to.sin_addr),
                  ntohs(addr_to.sin_port), inet_ntoa(addr_from.sin_addr),
                  node->src_port);

        close(sock_to);
        close(new_sock);
    }

    close(sock_from);

    return NULL;
}

/*
 * Add single net node.
 */

void node_add(nodes_t **nodes, int id,
              ipv4_t src_host, port_t src_port,
              ipv4_t dst_host, port_t dst_port)
{
    nodes_t *node;
    HASH_FIND_INT(*nodes, &id, node);

    if (node == NULL)
    {
        nodes_t *node_new = calloc(1, sizeof(*node_new));

        if (node_new != NULL)
        {
            node_new->id = id;

            if (pthread_create(&(node_new->handle), NULL, node_thread, (void *)&node_new) != 0)
            {
                free(node_new);
                return;
            }

            HASH_ADD_INT(*nodes, id, node_new);
            log_debug("* Added node entry (%d)\n", id);
        }
    }
}

/*
 * Delete single net node.
 */

void node_delete(nodes_t **nodes, int id)
{
    nodes_t *node;
    HASH_FIND_INT(*nodes, &id, node);

    if (node != NULL)
    {
        pthread_cancel(node->handle);
        HASH_DEL(*nodes, node);

        log_debug("* Deleted node entry (%d)\n", id);
    }
}

/*
 * Free single net node.
 */

void nodes_free(nodes_t *nodes)
{
    nodes_t *node;

    for (node = nodes; node != NULL; node = node->hh.next)
    {
        log_debug("* Freed net node (%d)\n", node->id);

        pthread_cancel(node->handle);
        HASH_DEL(nodes, node);

        free(node);
    }

    free(nodes);
}
