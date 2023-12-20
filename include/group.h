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

#ifndef _GROUP_H_
#define _GROUP_H_

#include <tlv.h>
#include <queue.h>
#include <stdlib.h>

typedef tlv_pkt_t group_t;

group_t *group_create(tlv_pkt_t *tlv_pkt);
tlv_pkt_t *group_tlv(group_t *group);

int group_enqueue(queue_t *queue, group_t *group);
ssize_t group_dequeue(queue_t *queue, group_t **group);

int group_tlv_enqueue(queue_t *queue, tlv_pkt_t *tlv_pkt);
ssize_t group_tlv_dequeue(queue_t *queue, tlv_pkt_t **tlv_pkt);

void group_destroy(group_t *group);

#endif