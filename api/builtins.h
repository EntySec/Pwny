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

#ifndef _BUILTINS_H_
#define _BUILTINS_H_

#include <sigar.h>

#include <api.h>
#include <c2.h>
#include <tabs.h>
#include <tlv_types.h>
#include <tlv.h>

#define BUILTIN_BASE 1

#define BUILTIN_QUIT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL)
#define BUILTIN_ADD_TAB_DISK \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 1)
#define BUILTIN_ADD_TAB_BUFFER \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 2)
#define BUILTIN_DELETE_TAB \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 3)
#define BUILTIN_SYSINFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 4)
#define BUILTIN_UUID \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 5)

#define TLV_TYPE_PLATFORM TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_VERSION  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 1)
#define TLV_TYPE_ARCH     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 2)
#define TLV_TYPE_MACHINE  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 3)
#define TLV_TYPE_VENDOR   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 4)

static tlv_pkt_t *builtin_quit(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT);
}

static tlv_pkt_t *builtin_add_tab_disk(c2_t *c2)
{
    char filename[128];
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, filename) > 0)
    {
        if (tabs_add(&c2->dynamic.tabs, c2->dynamic.t_count, filename, NULL, c2) == 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS);
            tlv_pkt_add_int(result, TLV_TYPE_TAB_ID, c2->dynamic.t_count);
            c2->dynamic.t_count++;

            return result;
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_add_tab_buffer(c2_t *c2)
{
    int tab_size;
    unsigned char *tab;
    tlv_pkt_t *result;

    if ((tab_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_TAB, &tab)) > 0)
    {
        if (tabs_add(&c2->dynamic.tabs, c2->dynamic.t_count, NULL, tab, c2) == 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS);
            tlv_pkt_add_int(result, TLV_TYPE_TAB_ID, c2->dynamic.t_count);
            c2->dynamic.t_count++;
            free(tab);

            return result;
        }
        else
        {
            free(tab);
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_delete_tab(c2_t *c2)
{
    int tab_id;

    tlv_pkt_get_int(c2->request, TLV_TYPE_TAB_ID, &tab_id);

    if (tabs_delete(&c2->dynamic.tabs, tab_id) == 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_uuid(c2_t *c2)
{
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    tlv_pkt_add_string(result, TLV_TYPE_UUID, c2->uuid);

    return result;
}

static tlv_pkt_t *builtin_sysinfo(c2_t *c2)
{
    int status;
    tlv_pkt_t *result;
    sigar_sys_info_t sysinfo;

    if ((status = sigar_sys_info_get(c2->sigar, &sysinfo)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar sysinfo (%s)\n",
                  sigar_strerror(c2->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    tlv_pkt_add_string(result, TLV_TYPE_PLATFORM, sysinfo.name);
    tlv_pkt_add_string(result, TLV_TYPE_VERSION, sysinfo.version);
    tlv_pkt_add_string(result, TLV_TYPE_ARCH, sysinfo.arch);
    tlv_pkt_add_string(result, TLV_TYPE_MACHINE, sysinfo.machine);
    tlv_pkt_add_string(result, TLV_TYPE_VENDOR, sysinfo.vendor);

    return result;
}

void register_builtin_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, BUILTIN_QUIT, builtin_quit);
    api_call_register(api_calls, BUILTIN_ADD_TAB_DISK, builtin_add_tab_disk);
    api_call_register(api_calls, BUILTIN_ADD_TAB_BUFFER, builtin_add_tab_buffer);
    api_call_register(api_calls, BUILTIN_DELETE_TAB, builtin_delete_tab);
    api_call_register(api_calls, BUILTIN_SYSINFO, builtin_sysinfo);
}

#endif
