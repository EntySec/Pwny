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

#ifndef _HTTP_CLIENT_H_
#define _HTTP_CLIENT_H_

#include <ev.h>
#include <curl/curl.h>
#include <pwny/queue.h>

#define HTTP_DATA_COMPRESS 1

#define HTTP_VERBOSE  1
#define HTTP_SKIP_TLS 2

#define HTTP_RESPONSE_OK 200

enum HTTP_REQUEST
{
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE
};

enum HTTP_AUTH
{
    HTTP_AUTH_NONE,
    HTTP_AUTH_BASIC,
    HTTP_AUTH_DIGEST
};

enum HTTP_CA
{
    HTTP_CA_NONE,
    HTTP_CA_PATH,
    HTTP_CA_BUNDLE
};

enum HTTP_PROXY
{
    HTTP_PROXY_NONE,
    HTTP_PROXY_HTTP,
    HTTP_PROXY_SOCKS5
};

struct http_request_data
{
    char *const *headers;
    int num_headers;

    char *cookies;
    char *referer;
    char *user_agent;

    unsigned int flags;
    const char *content_type;
    void *content;
    size_t content_length;
};

struct http_request_options
{
    enum HTTP_CA ca_type;
    const char *ca;

    struct
    {
        enum HTTP_PROXY type;
        enum HTTP_AUTH auth_type;

        const char *hostname;
        uint16_t port;

        const char *auth_user;
        const char *auth_pass;
    } proxy;

    unsigned int flags;

    enum HTTP_AUTH auth_type;
    const char *auth_user;
    const char *auth_pass;

    const char *pin;
};

struct http_client
{
    CURL *easy_handle;
    CURLcode result;

    char *uri;
    char error[CURL_ERROR_SIZE];

    void (*callback)(struct http_client *, void *data);
    void *data;

    void *content;
    size_t content_length;

    struct curl_slist *request_headers;
    struct curl_slist *response_headers;

    queue_t *response;
};

typedef void (*http_callback_t)(struct http_client *, void *data);

int http_response_code(struct http_client *client);
const char *http_response_header_value(struct http_client *client, const char *key);
int http_request(const char *uri, enum HTTP_REQUEST request, http_callback_t callback,
                 void *data, struct http_request_data *request_data, struct http_request_options *options);
void http_client_free(struct http_client *conn);

#endif
