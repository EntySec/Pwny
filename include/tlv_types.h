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

#define TLV_FILE_CHUNK 1024

#define TLV_TAG_CUSTOM(pool, base, call) \
                        (pool + base * 1000) + call

#define TLV_PIPE_CUSTOM(pool, base, type) \
                        (pool + base * 1000) + type

#define TLV_TYPE_CUSTOM(parent, base, child) \
                        (parent * 1000 + base * 100)  + child

#define TLV_TYPE_CHAR   1
#define TLV_TYPE_SHORT  2
#define TLV_TYPE_INT    3
#define TLV_TYPE_LONG   4

#define TLV_TYPE_UCHAR  5
#define TLV_TYPE_USHORT 6
#define TLV_TYPE_UINT   7
#define TLV_TYPE_ULONG  8

#define TLV_TYPE_LONGLONG 9
#define TLV_TYPE_FLOAT    10
#define TLV_TYPE_DOUBLE   11
#define TLV_TYPE_STRING   12
#define TLV_TYPE_BYTES    13
#define TLV_TYPE_GROUP    14

#define TLV_TYPE_TAG    TLV_TYPE_CUSTOM(TLV_TYPE_INT, 0, 1)
#define TLV_TYPE_STATUS TLV_TYPE_CUSTOM(TLV_TYPE_INT, 0, 2)
#define TLV_TYPE_PID    TLV_TYPE_CUSTOM(TLV_TYPE_INT, 0, 3)

#define TLV_TYPE_TAB_ID        TLV_TYPE_CUSTOM(TLV_TYPE_INT, 0, 4)

#define TLV_TYPE_TAB     TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, 0, 1)
#define TLV_TYPE_MIGRATE TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, 0, 2)

#define TLV_TYPE_UUID     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, 0, 1)
#define TLV_TYPE_FILENAME TLV_TYPE_CUSTOM(TLV_TYPE_STRING, 0, 2)
#define TLV_TYPE_PATH     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, 0, 3)

#endif