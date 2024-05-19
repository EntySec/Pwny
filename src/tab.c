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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ev.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <api.h>
#include <tab.h>
#include <log.h>
#include <link.h>
#include <queue.h>
#include <tunnel.h>

#include <tunnels/tunnels.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

static void tab_signal_handler(struct ev_loop *loop, ev_signal *w, int revents)
{
    switch (w->signum)
    {
        case SIGINT:
            log_debug("* TAB has SIGINT caught\n");
            ev_break(loop, EVBREAK_ALL);
            break;

        case SIGTERM:
            log_debug("* TAB has SIGTERM caught\n");
            ev_break(loop, EVBREAK_ALL);
            break;

        default:
            break;
    }
}

void tab_read(void *data)
{
    c2_t *c2;
    tab_t *tab;

    c2 = data;
    tab = c2->data;

    while (c2_dequeue_tlv(c2, &c2->request) > 0)
    {
        switch (api_process_c2(c2, tab->api_calls, NULL))
        {
            case API_BREAK:
                log_debug("* Received API_BREAK signal (%d)\n", API_BREAK);

                c2_enqueue_tlv(c2, c2->response);
                ev_break(c2->loop, EVBREAK_ALL);

                tlv_pkt_destroy(c2->response);
                tlv_pkt_destroy(c2->request);

                break;

            case API_CALLBACK:
                log_debug("* Received API_CALLBACK signal (%d)\n", API_CALLBACK);

                c2_enqueue_tlv(c2, c2->response);

                tlv_pkt_destroy(c2->response);
                tlv_pkt_destroy(c2->request);

                break;

            case API_SILENT:
                log_debug("* Received API_SILENT signal (%d)\n", API_SILENT);
                return;

            default:
                break;
        }
    }
}

void tab_write(void *data)
{
    c2_t *c2;

    c2 = data;
    tunnel_write(c2->tunnel, c2->tunnel->egress);
}

void tab_register_call(tab_t *tab, int tag, api_t handler)
{
    api_call_register(&tab->api_calls, tag, handler);
}

void tab_register_pipe(tab_t *tab, int type, pipe_callbacks_t callbacks)
{
    api_pipe_register(&tab->c2->pipes, type, callbacks);
}

tab_t *tab_create(void)
{
    tab_t *tab;
    int flags;

    tab = calloc(1, sizeof(*tab));

    if (tab == NULL)
    {
        return NULL;
    }

    tab->loop = ev_default_loop(TAB_EV_FLAGS);

    tab->api_calls = NULL;
    tab->tunnels = NULL;

    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(STDERR_FILENO, F_GETFL, 0);
    fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK);

    return tab;
}

void tab_setup(tab_t *tab)
{
    c2_t *c2;

    tab->c2 = NULL;

    register_pipe_api_calls(&tab->api_calls);
    register_tab_tunnels(&tab->tunnels);

    c2 = c2_add_uri(&tab->c2, 0, "ipc://", tab->tunnels);
    if (c2 == NULL)
    {
        return;
    }

    c2_set_links(c2, tab_read, tab_write, NULL, NULL);
    c2_setup(c2, tab->loop, NULL, tab);
    c2_start(c2);
}

int tab_start(tab_t *tab)
{
    ev_signal sigint_w, sigterm_w;

    ev_signal_init(&sigint_w, tab_signal_handler, SIGINT);
    ev_signal_start(tab->loop, &sigint_w);
    ev_signal_init(&sigterm_w, tab_signal_handler, SIGTERM);
    ev_signal_start(tab->loop, &sigterm_w);

    return ev_run(tab->loop, 0);
}

void tab_destroy(tab_t *tab)
{
    ev_break(tab->loop, EVBREAK_ALL);

    c2_free(tab->c2);

    api_calls_free(tab->api_calls);
    tunnels_free(tab->tunnels);

    free(tab);
}

static tlv_pkt_t *tab_term(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT);
}

void register_tab_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, TAB_TERM, tab_term);
}
