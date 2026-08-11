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

#include <ctype.h>
#include <stdlib.h>

#include <curl/curl.h>
#include <zlib.h>
#include <eio.h>

#include <pwny/log.h>
#include <pwny/http_client.h>

int http_response_code(struct http_client *client)
{
    long code;

    code = -1;
    curl_easy_getinfo(client->easy_handle, CURLINFO_RESPONSE_CODE, &code);

    return code;
}

static size_t http_write_cb(void *buffer, size_t size, size_t nmemb, void *data)
{
    size_t length;
    struct http_client *client;

    length = size * nmemb;
    client = data;

    if (queue_add_raw(client->response, buffer, length) != 0)
    {
        return 0;
    }

    return length;
}

static size_t http_header_cb(void *buffer, size_t size, size_t nmemb, void *data)
{
    long code;
    char *header;

    size_t length;
    size_t end;

    struct http_client *client;

    length = size * nmemb;
    client = data;

    curl_easy_getinfo(client->easy_handle, CURLINFO_RESPONSE_CODE, &code);
    if (code == 302)
    {
        return length;
    }

    if (length > 2)
    {
        header = malloc(length + 1);
        if (header)
        {
            memcpy(header, buffer, length);
            header[length] = '\0';

            for (end = length - 1; end > 0 && isspace(header[end]); end--)
            {
                header[end] = '\0';
            }

            client->response_headers = curl_slist_append(client->response_headers, header);
            free(header);
        }
    }

    return length;
}

static int http_request_complete(struct eio_req *request)
{
    struct http_client *client;

    client = request->data;
    if (client->callback)
    {
        client->callback(client, client->data);
    }

    http_client_free(client);
    return 0;
}

static void http_request_async(struct eio_req *request)
{
    struct http_client *client;

    client = request->data;
    client->result = curl_easy_perform(client->easy_handle);
}

static void *http_compress_content(const void *content, size_t length, size_t *compressed)
{
    int status;
    void *buffer;

    size_t compressed_size;
    z_stream strm = {0};

    if (length < 256)
    {
        log_debug("* HTTP content length less than 256\n");
        return NULL;
    }

    compressed_size = compressBound(length);
    buffer = malloc(compressed_size);

    if (buffer == NULL)
    {
        log_debug("* Failed to allocate memory for compressed data\n");
        return NULL;
    }

    status = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS | 16,
                          MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (status != Z_OK)
    {
        switch (status)
        {
            case Z_MEM_ERROR:
                log_debug("* Not enough memory for compression\n");
                break;
            case Z_BUF_ERROR:
                log_debug("* Unknown buffer error due to compression\n");
                break;
            default:
                break;
        }

        free(buffer);
        buffer = NULL;
        goto finalize;
    }

    strm.next_in = (Bytef *)content;
    strm.avail_in = length;
    strm.next_out = (Bytef *)buffer;
    strm.avail_out = length;

    status = deflate(&strm, Z_FINISH);

    if (status != Z_STREAM_END)
    {
        log_debug("* Unknown stream error during compression\n");
        free(buffer);
        buffer = NULL;
    }
    else
    {
        *compressed = strm.total_out;
    }

finalize:
    deflateEnd(&strm);
    return buffer;
}

const char *http_response_header_value(struct http_client *client, const char *key)
{
    char *search;
    int status;
    size_t length;
    struct curl_slist *header;

    search = NULL;

    if (client->response_headers == NULL)
    {
        return search;
    }

    status = asprintf(&search, "%s: ", key);

    if (status > 0 && search)
    {
        length = strlen(search);
        header = client->response_headers;

        do
        {
            if (!strncmp(search, header->data, length))
            {
                free(search);
                return header->data + length;
            }

            header = header->next;
        }
        while (header);
    }

    free(search);
    return NULL;
}

int http_request(const char *uri, enum HTTP_REQUEST request, http_callback_t callback,
                 void *data, struct http_request_data *request_data, struct http_request_options *options)
{
    int iter;
    int status;
    char *user;
    char *content_type;
    struct http_client *client;

    client = calloc(1, sizeof(*client));
    if (client == NULL)
    {
        return -1;
    }

    client->uri = strdup(uri);
    if (client->uri == NULL)
    {
        goto fail;
    }

    client->response = queue_create();
    if (client->response == NULL)
    {
        free(client->uri);

        goto fail;
    }

    client->callback = callback;
    client->data = data;

    client->easy_handle = curl_easy_init();
    if (client->easy_handle == NULL)
    {
        free(client->uri);
        queue_free(client->response);

        goto fail;
    }

    curl_easy_setopt(client->easy_handle, CURLOPT_URL, client->uri);
    curl_easy_setopt(client->easy_handle, CURLOPT_HEADERFUNCTION, http_header_cb);
	curl_easy_setopt(client->easy_handle, CURLOPT_HEADERDATA, client);
	curl_easy_setopt(client->easy_handle, CURLOPT_WRITEFUNCTION, http_write_cb);
	curl_easy_setopt(client->easy_handle, CURLOPT_WRITEDATA, client);
	curl_easy_setopt(client->easy_handle, CURLOPT_ERRORBUFFER, client->error);
	curl_easy_setopt(client->easy_handle, CURLOPT_PRIVATE, client);
	curl_easy_setopt(client->easy_handle, CURLOPT_FOLLOWLOCATION, 1L);

    curl_easy_setopt(client->easy_handle, CURLOPT_LOW_SPEED_TIME, 60L);
	curl_easy_setopt(client->easy_handle, CURLOPT_LOW_SPEED_LIMIT, 1L);

    curl_easy_setopt(client->easy_handle, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(client->easy_handle, CURLOPT_TIMEOUT, 60L);

    switch (request)
    {
    	case HTTP_GET:
			break;
		case HTTP_POST:
			curl_easy_setopt(client->easy_handle, CURLOPT_POST, 1L);
			break;
		case HTTP_PUT:
			curl_easy_setopt(client->easy_handle, CURLOPT_PUT, 1L);
			break;
		case HTTP_DELETE:
			curl_easy_setopt(client->easy_handle, CURLOPT_CUSTOMREQUEST, "DELETE");
			break;
	}

    if (request_data)
    {
		for (iter = 0; iter < request_data->num_headers; iter++)
		{
			client->request_headers =
				curl_slist_append(client->request_headers, request_data->headers[iter]);
		}

		if (request_data->cookies)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_COOKIEFILE, "");
			curl_easy_setopt(client->easy_handle, CURLOPT_COOKIELIST, request_data->cookies);
		}

		if (request_data->referer)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_REFERER, request_data->referer);
		}

		if (request_data->user_agent)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_USERAGENT, request_data->user_agent);
		}

		if (request_data->content)
		{
			content_type = NULL;

			status = asprintf(&content_type, "Content-Type: %s",
					          request_data->content_type ? request_data->content_type : "application/json");
			if (status > 0)
			{
				client->request_headers = curl_slist_append(client->request_headers, content_type);
                free(content_type);
			}

			if (request_data->flags & HTTP_DATA_COMPRESS)
			{
			    log_debug("* Will compress with Z\n");
				client->content = http_compress_content(request_data->content, request_data->content_length,
				                                        &client->content_length);
				if (client->content)
				{
					client->request_headers = curl_slist_append(client->request_headers,
								                                "Content-Encoding: gzip");
				}
			}

			if (client->content == NULL)
			{
				client->content = malloc(request_data->content_length);

				if (client->content)
				{
					memcpy(client->content, request_data->content, request_data->content_length);
					client->content_length = request_data->content_length;
				}
			}

			if (client->content)
			{
				curl_easy_setopt(client->easy_handle, CURLOPT_POSTFIELDS, client->content);
				curl_easy_setopt(client->easy_handle, CURLOPT_POSTFIELDSIZE, (long)client->content_length);
			}
		}
	}

    if (options)
    {
        if (options->ca_type == HTTP_CA_PATH)
        {
			curl_easy_setopt(client->easy_handle, CURLOPT_CAPATH, options->ca);
		}
		else if (options->ca_type == HTTP_CA_BUNDLE)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_CAINFO, options->ca);
		}

		if (options->proxy.type != HTTP_PROXY_NONE)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_PROXY, options->proxy.hostname);
			curl_easy_setopt(client->easy_handle, CURLOPT_PROXYPORT, options->proxy.port);

			if (options->proxy.auth_type != HTTP_AUTH_NONE)
			{
				user = NULL;
				status = asprintf(&user, "%s:%s",
						          options->proxy.auth_user ? options->proxy.auth_user : "",
						          options->proxy.auth_pass ? options->proxy.auth_pass : "");
				if (status > 0)
				{
					curl_easy_setopt(client->easy_handle, CURLOPT_PROXYUSERPWD, user);

					if (options->proxy.auth_type == HTTP_AUTH_BASIC)
					{
						curl_easy_setopt(client->easy_handle, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
					}
					else if (options->proxy.auth_type == HTTP_AUTH_DIGEST)
					{
						curl_easy_setopt(client->easy_handle, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
					}

					free(user);
				}
			}
		}

		if (options->flags & HTTP_VERBOSE)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_VERBOSE, 1L);
		}
		if (options->pin)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(client->easy_handle, CURLOPT_SSL_VERIFYHOST, 0L);
			curl_easy_setopt(client->easy_handle, CURLOPT_PINNEDPUBLICKEY, options->pin);
		}
		else if (options->flags & HTTP_SKIP_TLS)
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(client->easy_handle, CURLOPT_SSL_VERIFYHOST, 0L);
		}
		else
		{
			curl_easy_setopt(client->easy_handle, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(client->easy_handle, CURLOPT_SSL_VERIFYHOST, 2L);
		}
    }

    if (client->request_headers)
    {
		curl_easy_setopt(client->easy_handle, CURLOPT_HTTPHEADER, client->request_headers);
	}

	eio_custom(http_request_async, 0, http_request_complete, client);
	return 0;

fail:
	http_client_free(client);
	return -1;
}

void http_client_free(struct http_client *client)
{
    if (!client)
    {
        return;
    }

    free(client->uri);
    if (client->response)
    {
        queue_free(client->response);
    }

    if (client->request_headers)
    {
        curl_slist_free_all(client->request_headers);
    }

    if (client->response_headers)
    {
        curl_slist_free_all(client->response_headers);
    }

    if (client->easy_handle)
    {
        curl_easy_cleanup(client->easy_handle);
    }

    if (client->content)
    {
        free(client->content);
    }

    free(client);
}