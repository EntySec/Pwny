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

#ifndef _TAB_H_
#define _TAB_H_

#include <tlv.h>
#include <c2.h>

#include <unistd.h>
#include <sys/types.h>

#include <uthash/uthash.h>

typedef struct tabs {
    int tab_pool;
    pid_t tab_pid;
    int tab_fd;
    UT_hash_handle hh;
} tabs_t;

void tab_add(tabs_t **, int, unsigned char *);

int tab_delete(tabs_t **, int);
int tab_exit(tabs_t *);

int tab_lookup(tabs_t **, int, tlv_pkt_t *);
void tabs_free(tabs_t *);

#endif /* _TAB_H_ */
