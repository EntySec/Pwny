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

#include <key_list.h>

static key_list_node_t *key_list_get_node(key_list_t *list, int key)
{
    key_list_node_t *current;

    current = list->header;

    while (current != NULL)
    {
        if (key == current->key)
            return current;

        current = current->next;
    }

    return NULL;
}

static void key_list_remove_node(key_list_t *list, key_list_node_t *node)
{
    if (node == list->header)
        list->header = node->next;
    else
        node->prev->next = node->next;

    if (node->next != NULL)
        node->next->prev = node->prev;

    list->releaser(node->value);
    free(node);
    list->count--;
}

key_list_t *key_list_create(value_releaser_t releaser)
{
    key_list_t *list;

    list = (key_list_t *)malloc(sizeof(key_list_t));

    list->count = 0;
    list->header = NULL;
    list->releaser = releaser;

    return list;
}

void key_list_destroy(key_list_t *list)
{
    key_list_node_t *current;
    key_list_node_t *next;

    current = list->header;

    while (current != NULL)
    {
        next = current->next;
        list->releaser(current->value);
        free(current);
        current = next;
    }

    free(list);
}

int key_list_keyset(key_list_t *list, int *array, int array_size)
{
    int iter;
    key_list_node_t *current;

    if (array_size < list->count)
        return -1;

    iter = 0;
    current = list->header;

    while (current != NULL)
    {
        array[iter] = current->key;
        current = current->next;
        iter++;
    }

    return iter;
}

int key_list_find_key(key_list_t *list, int key)
{
    return key_list_get_node(list, key) != NULL;
}

int key_list_add(key_list_t *list, int key, value_t value)
{
    key_list_node_t *node;

    node = calloc(1, sizeof(key_list_node_t));

    if (node != NULL)
    {
        node->key = key;
        node->value = value;
        node->prev = NULL;
        node->next = NULL;

        if (list->header != NULL)
        {
            node->next = list->header;
            list->header->prev = node;
        }

        list->header = node;
        list->count++;

        return 0;
    }

    return -1;
}

int key_list_get(key_list_t *list, int key, value_t *value)
{
    key_list_node_t *node;

    node = key_list_get_node(list, key);

    if (node != NULL)
    {
        *value = node->value;
        return 0;
    }

    return -1;
}

int key_list_edit(key_list_t *list, int key, value_t value)
{
    key_list_node_t *node;

    node = key_list_get_node(list, key);

    if (node != NULL)
    {
        node->value = value;
        return 0;
    }

    return -1;
}

int key_list_delete(key_list_t *list, int key)
{
    key_list_node_t *node;

    node = key_list_get_node(list, key);

    if (node != NULL)
    {
        key_list_remove_node(list, node);
        return 0;
    }

    return -1;
}