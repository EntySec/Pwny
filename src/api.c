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
#include <string.h>
#include <stdlib.h>
#include <string.h>

#include <api.h>
#include <tabs.h>
#include <c2.h>
#include <tlv.h>
#include <log.h>
#include <calls.h>

#include <tlv_types.h>

#include <uthash/uthash.h>

api_signal_t api_process_c2(c2_t *c2)
{
    int tag;
    int status;
    int tab_id;

    log_debug("* Processing packet via API\n");

    if (tlv_pkt_get_int(c2->request, TLV_TYPE_TAG, &tag) != 0)
    {
        log_debug("* No tag was received by API\n");
        c2->response = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);

        return API_CALLBACK;
    }

    log_debug("* Read new tag (%d) by API\n", tag);

    if (c2->type != C2_TAB && tlv_pkt_get_int(c2->request, TLV_TYPE_TAB_ID, &tab_id) == 0)
    {
        if (tabs_lookup(&c2->dynamic.tabs, tab_id, c2->request) == 0)
        {
            tlv_pkt_destroy(c2->request);
            return API_SILENT;
        }

        c2->response = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);
        return API_CALLBACK;
    }

    if (api_call_make(&c2->dynamic.api_calls, c2, tag, &c2->response) != 0)
    {
        c2->response = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);
        return API_CALLBACK;
    }

    if (c2->response == NULL)
    {
        return API_SILENT;
    }

    if (tlv_pkt_get_int(c2->response, TLV_TYPE_STATUS, &status) == 0)
    {
        switch (status)
        {
            case API_CALL_QUIT:
                return API_BREAK;
            default:
                break;
        }
    }

    return API_CALLBACK;
}

tlv_pkt_t *api_craft_tlv_pkt(int status)
{
    tlv_pkt_t *c2_pkt;

    c2_pkt = tlv_pkt_create();
    tlv_pkt_add_int(c2_pkt, TLV_TYPE_STATUS, status);

    return c2_pkt;
}

void api_pipes_register(pipes_t **pipes)
{
    register_api_pipes(pipes);
}

void api_pipe_register(pipes_t **pipes, int type, pipe_callbacks_t callbacks)
{
    pipes_t *pipe;
    pipes_t *pipe_new;

    HASH_FIND_INT(*pipes, &type, pipe);

    if (pipe == NULL)
    {
        pipe_new = calloc(1, sizeof(*pipe_new));

        if (pipe_new != NULL)
        {
            pipe_new->type = type;
            pipe_new->pipes = NULL;
            pipe_new->callbacks = callbacks;

            HASH_ADD_INT(*pipes, type, pipe_new);
            log_debug("* Registered API pipe (type: %d)\n", type);
        }
    }
}

void api_calls_register(api_calls_t **api_calls)
{
    register_api_calls(api_calls);
}

void api_call_register(api_calls_t **api_calls, int tag, api_t handler)
{
    api_calls_t *api_call;
    api_calls_t *api_call_new;

    HASH_FIND_INT(*api_calls, &tag, api_call);

    if (api_call == NULL)
    {
        api_call_new = calloc(1, sizeof(*api_call_new));

        if (api_call_new != NULL)
        {
            api_call_new->tag = tag;
            api_call_new->handler = handler;

            HASH_ADD_INT(*api_calls, tag, api_call_new);
            log_debug("* Registered C2 API call tag (%d)\n", tag);
        }
    }
}

int api_call_make(api_calls_t **api_calls, c2_t *c2, int tag, tlv_pkt_t **result)
{
    api_calls_t *api_call;

    log_debug("* Looking for C2 API call tag (%d)\n", tag);
    HASH_FIND_INT(*api_calls, &tag, api_call);

    if (api_call == NULL)
    {
        log_debug("* C2 API call tag was not found (%d)\n", tag);
        *result = NULL;
        return -1;
    }

    *result = api_call->handler(c2);
    return 0;
}

void api_pipes_free(pipes_t *pipes)
{
    pipes_t *pipe;
    pipes_t *pipe_tmp;

    pipe_t *each_pipe;
    pipe_t *each_pipe_tmp;

    HASH_ITER(hh, pipes, pipe, pipe_tmp)
    {
        HASH_ITER(hh, pipe->pipes, each_pipe, each_pipe_tmp)
        {
            log_debug("* Freed API pipe (id: %d)\n", each_pipe->id);

            HASH_DEL(pipe->pipes, each_pipe);
            free(each_pipe);
        }

        free(pipes->pipes);
        log_debug("* Freed API pipe (type: %d)\n", pipe->type);

        HASH_DEL(pipes, pipe);
        free(pipe);
    }

    free(pipes);
}

void api_calls_free(api_calls_t *api_calls)
{
    api_calls_t *api_call;
    api_calls_t *api_call_tmp;

    HASH_ITER(hh, api_calls, api_call, api_call_tmp)
    {
        log_debug("* Freed C2 API call tag (%d)\n", api_call->tag);

        HASH_DEL(api_calls, api_call);
        free(api_call);
    }

    free(api_calls);
}
