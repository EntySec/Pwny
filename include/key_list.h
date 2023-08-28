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

#ifndef _KEY_LIST_H_
#define _KEY_LIST_H_

#include <stdlib.h>

#define KEY_LIST_FOREACH(L, V) key_list_node_t *_node = NULL; \
                               key_list_node_t *V; \
                               for (V = _node = L->header; _node != NULL; V = _node = _node->next)

typedef struct
{
    void *value;
} value_t;

typedef void (*value_releaser_t)(value_t value);

typedef struct key_list_node
{
    int key;
    value_t value;
    struct key_list_node *prev;
    struct key_list_node *next;
} key_list_node_t;

typedef struct
{
    int count;
    key_list_node_t *header;
    value_releaser_t releaser;
} key_list_t;

key_list_t *key_list_create(value_releaser_t);
void key_list_destroy(key_list_t *);

int key_list_keyset(key_list_t *, int *, int);
int key_list_find_key(key_list_t *, int);

int key_list_add(key_list_t *, int, value_t);
int key_list_get(key_list_t *, int, value_t *);
int key_list_edit(key_list_t *, int, value_t);
int key_list_delete(key_list_t *, int);

#endif /* _KEY_LIST_H_ */