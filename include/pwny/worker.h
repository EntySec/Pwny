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

/*! \file worker.h
 *  \brief Thread pool for non-blocking pipe operations
 */

#ifndef _WORKER_H_
#define _WORKER_H_

#include <ev.h>
#include <pwny/tlv.h>

#include <pthread.h>

#define WORKER_POOL_SIZE 4

/* Forward declaration */
typedef struct c2_table c2_t;

/* Task function signature */
typedef void (*worker_func_t)(void *arg);

/* A pending task for a worker thread */
typedef struct worker_task
{
    worker_func_t func;
    void *arg;
    struct worker_task *next;
} worker_task_t;

/* A completed response waiting to be flushed to the event loop */
typedef struct worker_response
{
    c2_t *c2;
    tlv_pkt_t *response;
    tlv_pkt_t *request;
    struct worker_response *next;
} worker_response_t;

typedef struct worker_pool
{
    int num_threads;
    int shutdown;

    /* Task queue (workers pull from here) */
    worker_task_t *task_head;
    worker_task_t *task_tail;

    /* Response queue (filled by workers, drained by event loop) */
    worker_response_t *resp_head;
    worker_response_t *resp_tail;

    /* libev async watcher to signal the event loop */
    struct ev_async async_watcher;
    struct ev_loop *loop;

    pthread_mutex_t task_lock;
    pthread_mutex_t resp_lock;
    pthread_cond_t task_cond;
    pthread_t *threads;
} worker_pool_t;

worker_pool_t *worker_pool_create(struct ev_loop *loop, int num_threads);
void worker_pool_destroy(worker_pool_t *pool);

int worker_submit(worker_pool_t *pool, worker_func_t func, void *arg);
void worker_push_response(worker_pool_t *pool, c2_t *c2,
                          tlv_pkt_t *response, tlv_pkt_t *request);

#endif
