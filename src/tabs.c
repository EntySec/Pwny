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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ev.h>

#include <pwny/tabs.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/log.h>
#include <pwny/tlv.h>
#include <pwny/queue.h>
#include <pwny/group.h>
#include <pwny/pipe.h>

#include <uthash/uthash.h>


/*
 * =============================================================
 * POSIX: Child-process tabs with pipe-based IPC.
 *
 * Each tab is a standalone executable spawned via fork/exec
 * (or process hollowing on Windows). Communication happens
 * over inherited stdin/stdout pipes using TLV group framing.
 * =============================================================
 */

#include <pwny/link.h>

extern char **environ;

void tabs_err(void *data)
{
    tabs_t *tab;
    queue_t *queue;
    char *message;
    size_t length;

    tab = data;
    queue = tab->child->err_queue.queue;
    length = queue->bytes;
    message = malloc(length + 1);

    if (message != NULL)
    {
        queue_remove(queue, (void *)message, length);
        message[length] = '\0';

        log_debug("[id: %d, pid: %d] %s\n", tab->id, tab->child->pid, message);
        free(message);
    }
}

void tabs_exit(void *data)
{
    tabs_t *tab;

    tab = data;
    (void)tab;
}

void tabs_out(void *data)
{
    tabs_t *tab;
    tlv_pkt_t *tlv_pkt;
    queue_t *queue;

    tab = data;
    queue = tab->child->out_queue.queue;

    if (group_tlv_dequeue(queue, &tlv_pkt, NULL) > 0)
    {
        group_tlv_enqueue(tab->c2->tunnel->egress, tlv_pkt, tab->c2->crypt);
        tlv_pkt_destroy(tlv_pkt);
    }

    if (tab->c2->write_link)
    {
        tab->c2->write_link(tab->c2->link_data);
    }
}

int tabs_add(tabs_t **tabs, int id,
             char *filename,
             unsigned char *image,
             size_t length,
             c2_t *c2)
{
    tabs_t *tab;
    tabs_t *tab_new;
    child_options_t options;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab == NULL)
    {
        tab_new = calloc(1, sizeof(*tab_new));

        if (tab_new != NULL)
        {
            options.args = NULL;
            options.env = environ;
            options.flags = CHILD_FORK;
            options.length = length;

            tab_new->id = id;
            tab_new->c2 = c2;
            tab_new->child = child_create(filename, image, &options);

            if (tab_new->child == NULL)
            {
                free(tab_new);
                return -1;
            }

            child_set_links(tab_new->child,
                            tabs_out, tabs_err, tabs_exit,
                            tab_new);
            HASH_ADD_INT(*tabs, id, tab_new);
            log_debug("* Added TAB entry (%d) (pid: %d)\n", id, tab_new->child->pid);
            return 0;
        }
    }

    return -1;
}

int tabs_lookup(tabs_t **tabs, int id, tlv_pkt_t *tlv_pkt)
{
    tabs_t *tab;
    group_t *group;

    log_debug("* Searching for TAB entry (%d)\n", id);
    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        log_debug("* Found TAB entry (%d)\n", id);

        group = group_create(tlv_pkt, NULL);

        log_debug("* Writing (%d) bytes to TAB\n", group->bytes);
        child_write(tab->child, group->buffer, group->bytes);

        group_destroy(group);
        return 0;
    }

    log_debug("* TAB was not found (%d)\n", id);
    return -1;
}

int tabs_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        child_destroy(tab->child);
        HASH_DEL(*tabs, tab);
        free(tab);

        log_debug("* Deleted TAB entry (%d)\n", id);
        return 0;
    }

    return -1;
}

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;
    tabs_t *tab_tmp;

    HASH_ITER(hh, tabs, tab, tab_tmp)
    {
        log_debug("* Freed TAB entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        if (tab->child)
        {
            if (tab->child->status == CHILD_ALIVE)
            {
                child_kill(tab->child);
            }

            child_destroy(tab->child);
        }

        free(tab);
    }

    free(tabs);
}

