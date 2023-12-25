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

#ifndef _PLAYER_H_
#define _PLAYER_H_

#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>

#import <MediaPlayer/MediaPlayer.h>

#define PLAYER_BASE 7

#define PLAYER_INFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PLAYER_BASE, \
                       API_CALL)
#define PLAYER_PLAY \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PLAYER_BASE, \
                       API_CALL + 1)
#define PLAYER_PAUSE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PLAYER_BASE, \
                       API_CALL + 2)
#define PLAYER_NEXT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PLAYER_BASE, \
                       API_CALL + 3)
#define PLAYER_BACK \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PLAYER_BASE, \
                       API_CALL + 4)

#define TLV_TYPE_PLAYER_TITLE  TLV_TYPE_CUSTOM(TLV_TYPE_INT, CAM_BASE, API_TYPE)
#define TLV_TYPE_PLAYER_ALBUM  TLV_TYPE_CUSTOM(TLV_TYPE_INT, CAM_BASE, API_TYPE + 1)
#define TLV_TYPE_PLAYER_ARTIST TLV_TYPE_CUSTOM(TLV_TYPE_INT, CAM_BASE, API_TYPE + 2)

typedef NS_ENUM(NSInteger, MRCommand) {
    kMRPlay = 0,
    kMRPause = 1,
    kMRNextTrack = 4,
    kMRPreviousTrack = 5,
};
Boolean MRMediaRemoteSendCommand(MRCommand command, id userInfo);

static tlv_pkt_t *player_info(c2_t *c2)
{
    tlv_pkt_t *result;
    MPMediaItem *song;

    char *title;
    char *album;
    char *artist;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    song = [[MPMusicPlayerController systemMusicPlayer] nowPlayingItem];

    title = (char *)[[song valueForProperty:MPMediaItemPropertyTitle] UTF8String];
    album = (char *)[[song valueForProperty:MPMediaItemPropertyAlbumTitle] UTF8String];
    artist = (char *)[[song valueForProperty:MPMediaItemPropertyArtist] UTF8String];

    if (title != NULL)
    {
        tlv_pkt_add_string(result, TLV_TYPE_PLAYER_TITLE, title);
    }

    if (album != NULL)
    {
        tlv_pkt_add_string(result, TLV_TYPE_PLAYER_ALBUM, album);
    }

    if (artist != NULL)
    {
        tlv_pkt_add_string(result, TLV_TYPE_PLAYER_ARTIST, artist);
    }

    return result;
}

static tlv_pkt_t *player_play(c2_t *c2)
{
    MRMediaRemoteSendCommand(kMRPlay, nil);
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *player_pause(c2_t *c2)
{
    MRMediaRemoteSendCommand(kMRPause, nil);
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *player_next(c2_t *c2)
{
    MRMediaRemoteSendCommand(kMRNextTrack, nil);
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *player_back(c2_t *c2)
{
    MRMediaRemoteSendCommand(kMRPreviousTrack, nil);
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

void register_player_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, PLAYER_INFO, player_info);
    api_call_register(api_calls, PLAYER_PLAY, player_play);
    api_call_register(api_calls, PLAYER_PAUSE, player_pause);
    api_call_register(api_calls, PLAYER_NEXT, player_next);
    api_call_register(api_calls, PLAYER_BACK, player_back);
}

#endif