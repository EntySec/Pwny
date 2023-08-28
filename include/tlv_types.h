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

#ifndef _TLV_TYPES_H_
#define _TLV_TYPES_H_

#define TLV_TYPE_CHAR   (1 << 16)
#define TLV_TYPE_SHORT  (1 << 17)
#define TLV_TYPE_INT    (1 << 18)
#define TLV_TYPE_LONG   (1 << 19)

#define TLV_TYPE_UCHAR  (1 << 20)
#define TLV_TYPE_USHORT (1 << 21)
#define TLV_TYPE_UINT   (1 << 22)
#define TLV_TYPE_ULONG  (1 << 23)

#define TLV_TYPE_LONGLONG (1 << 24)
#define TLV_TYPE_FLOAT    (1 << 25)
#define TLV_TYPE_DOUBLE   (1 << 26)
#define TLV_TYPE_STRING   (1 << 27)
#define TLV_TYPE_BYTES    (1 << 28)
#define TLV_TYPE_TLV      (1 << 29)

#define TLV_TYPE_TAG    (TLV_TYPE_INT | 1)
#define TLV_TYPE_STATUS (TLV_TYPE_INT | 2)
#define TLV_TYPE_PID    (TLV_TYPE_INT | 3)

#define TLV_TYPE_NODE_ID       (TLV_TYPE_INT | 4)
#define TLV_TYPE_NODE_SRC_ADDR (TLV_TYPE_INT | 5)
#define TLV_TYPE_NODE_SRC_PORT (TLV_TYPE_INT | 6)
#define TLV_TYPE_NODE_DST_ADDR (TLV_TYPE_INT | 7)
#define TLV_TYPE_NODE_DST_PORT (TLV_TYPE_INT | 8)
#define TLV_TYPE_TAB_ID        (TLV_TYPE_INT | 9)
#define TLV_TYPE_TAB_SIZE      (TLV_TYPE_INT | 10)
#define TLV_TYPE_MIGRATE_SIZE  (TLV_TYPE_INT | 11)

#define TLV_TYPE_MIGRATE_PID   (TLV_TYPE_PID | 1)

#define TLV_TYPE_TAB     (TLV_TYPE_BYTES | 1)
#define TLV_TYPE_MIGRATE (TLV_TYPE_BYTES | 2)

#define TLV_TYPE_UUID   (TLV_TYPE_STRING | 1)

#endif /* _TLV_TYPES_H_ */