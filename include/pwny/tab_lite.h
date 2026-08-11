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

#ifndef _TAB_LITE_H_
#define _TAB_LITE_H_

#include <ev.h>

#include <pwny/tlv.h>
#include <pwny/tlv_types.h>
#include <pwny/queue.h>

#include <uthash/uthash.h>

/*
 * TAB_LITE_TERM must equal TAB_TERM from tab.h:
 *   TLV_TAG_CUSTOM(API_CALL_INTERNAL, TAB_BASE + 1, API_CALL)
 *   = (1 | 3 << 2) | (1 << 8)
 *   = 13 | 256 = 269
 */

#define TAB_LITE_TERM 269

#define TAB_LITE_EV_FLAGS (EVFLAG_NOENV | EVBACKEND_SELECT)

#define TAB_BASE 2

/* Tag pool constants (match api.h without pulling it in) */
#define API_CALL          1
#define API_CALL_INTERNAL 1
#define API_CALL_STATIC   2
#define API_CALL_DYNAMIC  3

/* Matches api_status_t values from api.h */
#define TAB_STATUS_QUIT             0
#define TAB_STATUS_SUCCESS          1
#define TAB_STATUS_FAIL             2
#define TAB_STATUS_WAIT             3
#define TAB_STATUS_NOT_IMPLEMENTED  4

/*
 * Lightweight C2 stand-in. The only field handlers access is
 * `request` (same offset/name as in the full c2_t).
 */
typedef struct
{
    tlv_pkt_t *request;
} tab_lite_c2_t;

/* API handler function type — compatible signature with api_t */
typedef tlv_pkt_t *(*tab_api_t)(tab_lite_c2_t *);

/* Hash-table entry for registered API handlers */
typedef struct
{
    int tag;
    tab_api_t handler;
    UT_hash_handle hh;
} tab_api_entry_t;

/* Lightweight tab runtime context */
typedef struct
{
    struct ev_loop *loop;
    tab_api_entry_t *api_calls;
    queue_t *ingress;
    queue_t *egress;
} tab_lite_t;

/* Public API */
tab_lite_t *tab_lite_create(void);
void tab_lite_setup(tab_lite_t *tab);
void tab_lite_register_call(tab_lite_t *tab, int tag, tab_api_t handler);
int tab_lite_start(tab_lite_t *tab);
void tab_lite_destroy(tab_lite_t *tab);

/* Utility: craft a response TLV with status, preserving TAG and TAB_ID */
tlv_pkt_t *tab_lite_craft_response(int status, tlv_pkt_t *request);

#endif
