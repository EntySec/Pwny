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
#include <fcntl.h>
#include <errno.h>
#include <log.h>
#include <ev.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>

#include <net.h>
#include <link.h>
#include <queue.h>

int net_block_sock(int sock)
{
#ifdef _WIN32
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

void net_set_links(net_t *net,
                   link_t read_link,
                   link_t write_link,
                   void *data)
{
    net->read_link = read_link;
    net->write_link = write_link;
    net->link_data = data != NULL ? data : net;
}

int net_tls_start(net_t *net)
{
    int error;
    net_tls_t *net_tls;
    const char *pers;

    net_tls = calloc(1, sizeof(*net_tls));

    if (net_tls == NULL)
    {
        return -1;
    }

    pers = "ssl_client";

    mbedtls_ssl_init(&net_tls->ssl);
    mbedtls_ssl_config_init(&net_tls->conf);
    mbedtls_ctr_drbg_init(&net_tls->ctr_drbg);
    mbedtls_entropy_init(&net_tls->entropy);

    if (mbedtls_ctr_drbg_seed(&net_tls->ctr_drbg, mbedtls_entropy_func, &net_tls->entropy, (const unsigned char *)pers, strlen(pers)) != 0)
    {
        goto fail;
    }

    if (mbedtls_ssl_config_defaults(&net_tls->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
        goto fail;
    }

    mbedtls_ssl_conf_authmode(&net_tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&net_tls->conf, mbedtls_ctr_drbg_random, &net_tls->ctr_drbg);

    if (mbedtls_ssl_setup(&net_tls->ssl, &net_tls->conf) != 0)
    {
        goto fail;
    }

    mbedtls_ssl_set_bio(&net_tls->ssl, &net->sock, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((error = mbedtls_ssl_handshake(&net_tls->ssl)) != 0)
    {
        if (error != MBEDTLS_ERR_SSL_WANT_READ && error != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            goto fail;
        }
    }

    net->tls = net_tls;

    return 0;

fail:
    net_tls_free(net_tls);
    return -1;
}

void net_tls_free(net_tls_t *net_tls)
{
    mbedtls_ssl_close_notify(&net_tls->ssl);
    mbedtls_ssl_free(&net_tls->ssl);
    mbedtls_ssl_config_free(&net_tls->conf);
    mbedtls_ctr_drbg_free(&net_tls->ctr_drbg);
    mbedtls_entropy_free(&net_tls->entropy);

    free(net_tls);
}

void net_start(net_t *net)
{
    const char *pers;

    if (net->proto == NET_PROTO_TLS)
    {
        if (net_tls_start(net) != 0)
        {
            net->proto = NET_PROTO_TCP;
        }
    }

    ev_io_init(&net->io, net_read, net->sock, EV_READ);
    net->io.data = net;
    ev_io_start(net->loop, &net->io);
}

void net_setup(net_t *net, struct ev_loop *loop)
{
    net->loop = loop;
}

net_t *net_create(int sock, int proto)
{
    net_t *net;

    net = calloc(1, sizeof(*net));

    if (net != NULL)
    {
        if ((net->ingress = queue_create()) == NULL)
        {
            goto fail;
        }

        if ((net->egress = queue_create()) == NULL)
        {
            goto fail;
        }

        net->sock = sock;
        net->proto = proto;

        return net;
    }

    return NULL;

fail:
    net_free(net);
    return NULL;
}

void net_read_file(net_t *net)
{
    size_t bytes;

    log_debug("* Read FILE event initialized (%d)\n", net->sock);

    if ((bytes = queue_from_fd(net->ingress, net->sock)) > 0)
    {
        log_debug("* Read bytes via FILE (%d) - (%d)\n", net->sock, bytes);

        if (net->read_link)
        {
            net->read_link(net->link_data);
        }
    }
}

void net_read_tls(net_t *net)
{
    int stat;
    int bytes;
    char buffer[NET_QUEUE_SIZE];

    log_debug("* Read TLS event initialized (%d)\n", net->sock);

    while ((stat = mbedtls_ssl_read(&net->tls->ssl, (unsigned char *)buffer, sizeof(buffer))) > 0)
    {
        log_debug("* Read bytes via TLS (%d) - (%d)\n", net->sock, stat);
        queue_add_raw(net->ingress, buffer, stat);
        bytes += stat;
    }

    if (bytes > 0 && net->read_link)
    {
        net->read_link(net->link_data);
    }
}

void net_read_tcp(net_t *net)
{
    int error;
    size_t bytes;
    ssize_t stat;
    char buffer[NET_QUEUE_SIZE];

    log_debug("* Read TCP event initialized (%d)\n", net->sock);

    while ((stat = read(net->sock, buffer, sizeof(buffer))) > 0)
    {
        log_debug("* Read bytes via TCP (%d) - (%d)\n", net->sock, stat);
        queue_add_raw(net->ingress, buffer, stat);
        bytes += stat;
    }

    error = errno;

    if (bytes > 0 && net->read_link)
    {
        net->read_link(net->link_data);
    }

    if (stat == 0)
    {
        log_debug("* Read TCP connection shutdown (%d)\n", net->sock);
        ev_io_stop(net->loop, &net->io);
    }
    else if (stat == -1 && error != EAGAIN && error != EINPROGRESS && error != EWOULDBLOCK)
    {
        log_debug("* Read TCP connection terminated (%d)\n", net->sock);
        ev_io_stop(net->loop, &net->io);
    }
}

void net_write_file(net_t *net)
{
    size_t size;
    void *buffer;

    if (net->egress->bytes <= 0)
    {
        return;
    }

    while ((size = queue_remove_all(net->egress, &buffer)) > 0)
    {
        log_debug("* Writing bytes to FILE (%d) - (%d)\n", net->sock, size);
        write(net->sock, buffer, size);
        free(buffer);
    }
}

void net_write_tls(net_t *net)
{
    size_t size;
    int stat;
    int offset;
    void *buffer;

    buffer = NULL;
    offset = 0;

    if (net->egress->bytes <= 0)
    {
        return;
    }

    while ((size = queue_remove_all(net->egress, &buffer)) > 0)
    {
        log_debug("* Writing bytes to TLS (%d) - (%d)\n", net->sock, size);

        do
        {
            stat = mbedtls_ssl_write(&net->tls->ssl, buffer + offset, size - offset);

            if (stat > 0)
            {
                offset += stat;
            }

            log_debug("* Write bytes via TLS (%d) - (%d)\n", net->sock, stat);
        }
        while (stat > 0);

        free(buffer);
    }
}

void net_write_tcp(net_t *net)
{
    size_t size;
    ssize_t stat;
    ssize_t offset;
    void *buffer;

    buffer = NULL;
    offset = 0;

    if (net->egress->bytes <= 0)
    {
        return;
    }

    while ((size = queue_remove_all(net->egress, &buffer)) > 0)
    {
        log_debug("* Writing bytes to TCP (%d) - (%d)\n", net->sock, size);

        do
        {
            stat = send(net->sock, buffer + offset, size - offset, 0);

            if (stat > 0)
            {
                offset += stat;
            }

            log_debug("* Write bytes via TCP (%d) - (%d)\n", net->sock, stat);
        }
        while (stat > 0);

        free(buffer);
    }
}

void net_read(struct ev_loop *loop, struct ev_io *w, int events)
{
    net_t *net;

    net = w->data;

    switch (net->proto)
    {
        case NET_PROTO_TCP:
            net_read_tcp(net);
            break;

        case NET_PROTO_FILE:
            net_read_file(net);
            break;

        case NET_PROTO_TLS:
            net_read_tls(net);
            break;

        default:
            break;
    }
}

void net_write(net_t *net)
{
    switch (net->proto)
    {
        case NET_PROTO_TCP:
            net_write_tcp(net);
            break;

        case NET_PROTO_FILE:
            net_write_file(net);
            break;

        case NET_PROTO_TLS:
            net_write_tls(net);
            break;

        default:
            break;
    }
}

void net_free(net_t *net)
{
    if (net != NULL)
    {
        ev_io_stop(net->loop, &net->io);

        queue_free(net->ingress);
        queue_free(net->egress);

        if (net->proto == NET_PROTO_TLS)
        {
            net_tls_free(net->tls);
        }

        close(net->sock);
        free(net);
    }
}
