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

#include <stdlib.h>
#include <string.h>

#include <pwny/worker.h>
#include <pwny/c2.h>
#include <pwny/log.h>

/*
 * Platform-specific worker thread entry points
 */


static void *worker_thread_func(void *arg)
{
    worker_pool_t *pool;
    worker_task_t *task;

    pool = (worker_pool_t *)arg;

    while (1)
    {
        pthread_mutex_lock(&pool->task_lock);

        while (pool->task_head == NULL && !pool->shutdown)
        {
            pthread_cond_wait(&pool->task_cond, &pool->task_lock);
        }

        if (pool->shutdown)
        {
            pthread_mutex_unlock(&pool->task_lock);
            break;
        }

        task = pool->task_head;
        pool->task_head = task->next;

        if (pool->task_head == NULL)
        {
            pool->task_tail = NULL;
        }

        pthread_mutex_unlock(&pool->task_lock);

        task->func(task->arg);
        free(task);
    }

    return NULL;
}


/*
 * ev_async callback — runs on event loop thread to flush
 * completed responses back through the C2 channel.
 */

static void worker_flush_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
    worker_pool_t *pool;
    worker_response_t *resp;
    worker_response_t *resp_list;

    pool = (worker_pool_t *)w->data;

    /* Atomically grab entire response list */

    pthread_mutex_lock(&pool->resp_lock);

    resp_list = pool->resp_head;
    pool->resp_head = NULL;
    pool->resp_tail = NULL;

    pthread_mutex_unlock(&pool->resp_lock);

    /* Flush all responses from the event loop thread */

    while (resp_list != NULL)
    {
        resp = resp_list;
        resp_list = resp->next;

        c2_enqueue_tlv(resp->c2, resp->response);

        tlv_pkt_destroy(resp->response);
        tlv_pkt_destroy(resp->request);
        free(resp);
    }
}

/*
 * Create a worker thread pool attached to an ev_loop.
 */

worker_pool_t *worker_pool_create(struct ev_loop *loop, int num_threads)
{
    int i;
    worker_pool_t *pool;

    pool = calloc(1, sizeof(*pool));

    if (pool == NULL)
    {
        return NULL;
    }

    pool->num_threads = num_threads;
    pool->shutdown = 0;
    pool->loop = loop;

    pool->task_head = NULL;
    pool->task_tail = NULL;
    pool->resp_head = NULL;
    pool->resp_tail = NULL;

    pthread_mutex_init(&pool->task_lock, NULL);
    pthread_mutex_init(&pool->resp_lock, NULL);
    pthread_cond_init(&pool->task_cond, NULL);
    pool->threads = calloc(num_threads, sizeof(pthread_t));

    if (pool->threads == NULL)
    {
        free(pool);
        return NULL;
    }

    /* Setup ev_async watcher for flushing responses */

    ev_async_init(&pool->async_watcher, worker_flush_cb);
    pool->async_watcher.data = pool;
    ev_async_start(loop, &pool->async_watcher);

    /* Spawn worker threads */

    for (i = 0; i < num_threads; i++)
    {
        pthread_create(&pool->threads[i], NULL, worker_thread_func, pool);
    }

    log_debug("* Worker pool created with %d threads\n", num_threads);
    return pool;
}

/*
 * Destroy the worker pool, joining all threads.
 */

void worker_pool_destroy(worker_pool_t *pool)
{
    int i;
    worker_task_t *task;
    worker_response_t *resp;

    if (pool == NULL)
    {
        return;
    }

    pthread_mutex_lock(&pool->task_lock);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->task_cond);
    pthread_mutex_unlock(&pool->task_lock);

    for (i = 0; i < pool->num_threads; i++)
    {
        pthread_join(pool->threads[i], NULL);
    }

    pthread_mutex_destroy(&pool->task_lock);
    pthread_mutex_destroy(&pool->resp_lock);
    pthread_cond_destroy(&pool->task_cond);

    /* Free remaining tasks */

    while (pool->task_head != NULL)
    {
        task = pool->task_head;
        pool->task_head = task->next;
        free(task);
    }

    /* Discard remaining responses (shutdown — no point sending) */

    while (pool->resp_head != NULL)
    {
        resp = pool->resp_head;
        pool->resp_head = resp->next;

        tlv_pkt_destroy(resp->response);
        tlv_pkt_destroy(resp->request);
        free(resp);
    }

    ev_async_stop(pool->loop, &pool->async_watcher);
    free(pool->threads);
    free(pool);

    log_debug("* Worker pool destroyed\n");
}

/*
 * Submit a task to the thread pool.
 */

int worker_submit(worker_pool_t *pool, worker_func_t func, void *arg)
{
    worker_task_t *task;

    if (pool == NULL || pool->shutdown)
    {
        return -1;
    }

    task = calloc(1, sizeof(*task));

    if (task == NULL)
    {
        return -1;
    }

    task->func = func;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->task_lock);

    if (pool->task_tail != NULL)
    {
        pool->task_tail->next = task;
    }
    else
    {
        pool->task_head = task;
    }

    pool->task_tail = task;

    pthread_cond_signal(&pool->task_cond);
    pthread_mutex_unlock(&pool->task_lock);

    return 0;
}

/*
 * Push a completed response from a worker thread.
 * The event loop will flush it via ev_async.
 */

void worker_push_response(worker_pool_t *pool, c2_t *c2,
                          tlv_pkt_t *response, tlv_pkt_t *request)
{
    worker_response_t *resp;

    resp = calloc(1, sizeof(*resp));

    if (resp == NULL)
    {
        tlv_pkt_destroy(response);
        tlv_pkt_destroy(request);
        return;
    }

    resp->c2 = c2;
    resp->response = response;
    resp->request = request;
    resp->next = NULL;

    pthread_mutex_lock(&pool->resp_lock);

    if (pool->resp_tail != NULL)
    {
        pool->resp_tail->next = resp;
    }
    else
    {
        pool->resp_head = resp;
    }

    pool->resp_tail = resp;
    pthread_mutex_unlock(&pool->resp_lock);

    /* Signal event loop to flush */
    ev_async_send(pool->loop, &pool->async_watcher);
}
