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

#ifndef _TABS_H_
#define _TABS_H_

#include <unistd.h>
#include <sys/types.h>

#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>
#include <child.h>

#include <uthash/uthash.h>

typedef struct c2_table c2_t;

typedef struct tabs_table
{
    int id;
    child_t *child;
    c2_t *c2;
    UT_hash_handle hh;
} tabs_t;

void tabs_err(void *data);
void tabs_out(void *data);

int tabs_add(tabs_t **tabs, int id,
             char *filename,
             unsigned char *image,
             size_t length,
             c2_t *c2);

int tabs_delete(tabs_t **tabs, int id);
int tabs_lookup(tabs_t **tabs, int id, tlv_pkt_t *tlv_pkt);

void tabs_free(tabs_t *tabs);

#endif