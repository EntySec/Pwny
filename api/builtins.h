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

#ifndef _BUILTINS_H_
#define _BUILTINS_H_

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sigar.h>
#include <time.h>
#include <eio.h>

#include <mbedtls/pk.h>

#ifndef __windows__
#include <pwd.h>
#endif

#include <api.h>
#include <c2.h>
#include <tabs.h>
#include <tlv_types.h>
#include <tlv.h>
#include <group.h>
#include <crypt.h>
#include <log.h>

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
#define BUILTIN_TIME \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 5)
#define BUILTIN_WHOAMI \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 6)
#define BUILTIN_UUID \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 7)
#define BUILTIN_SECURE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 8)
#define BUILTIN_UNSECURE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 9)

#define TLV_TYPE_PLATFORM  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_VERSION   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 1)
#define TLV_TYPE_ARCH      TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 2)
#define TLV_TYPE_MACHINE   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 3)
#define TLV_TYPE_VENDOR    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, BUILTIN_BASE, API_TYPE + 4)

#define TLV_TYPE_RAM_USED  TLV_TYPE_CUSTOM(TLV_TYPE_INT, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_RAM_TOTAL TLV_TYPE_CUSTOM(TLV_TYPE_INT, BUILTIN_BASE, API_TYPE + 1)
#define TLV_TYPE_FLAGS     TLV_TYPE_CUSTOM(TLV_TYPE_INT, BUILTIN_BASE, API_TYPE + 2)

#define TLV_TYPE_PUBLIC_KEY  TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, BUILTIN_BASE, API_TYPE)
#define TLV_TYPE_KEY         TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, BUILTIN_BASE, API_TYPE + 1)

static tlv_pkt_t *builtin_quit(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT, c2->request);
}

static tlv_pkt_t *builtin_add_tab_disk(c2_t *c2)
{
    core_t *core;
    char filename[128];
    tlv_pkt_t *result;

    core = c2->data;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_FILENAME, filename) > 0)
    {
        if (tabs_add(&core->tabs, core->t_count, filename, NULL, strlen(filename)+1, c2) == 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_u32(result, TLV_TYPE_TAB_ID, core->t_count);
            core->t_count++;

            return result;
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *builtin_add_tab_buffer(c2_t *c2)
{
    core_t *core;
    int tab_size;
    unsigned char *tab;
    tlv_pkt_t *result;

    core = c2->data;

    if ((tab_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_TAB, &tab)) > 0)
    {
        if (tabs_add(&core->tabs, core->t_count, NULL, tab, tab_size, c2) == 0)
        {
            result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_u32(result, TLV_TYPE_TAB_ID, core->t_count);
            core->t_count++;
            free(tab);

            return result;
        }
        else
        {
            free(tab);
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *builtin_delete_tab(c2_t *c2)
{
    core_t *core;
    int tab_id;

    core = c2->data;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_INT, &tab_id);

    if (tabs_delete(&core->tabs, tab_id) == 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

static tlv_pkt_t *builtin_time(c2_t *c2)
{
    tlv_pkt_t *result;
    char date_time[128];
    struct tm local_time;
    time_t time_ctx;

#ifndef __windows__
    memset(date_time, '\0', 128);
    time_ctx = time(NULL);

    localtime_r(&time_ctx, &local_time);
    strftime(date_time, sizeof(date_time) - 1, "%Y-%m-%d %H:%M:%S %Z (UTC%z)", &local_time);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_STRING, date_time);
#else
    result = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);
#endif

    return result;
}

static tlv_pkt_t *builtin_sysinfo(c2_t *c2)
{
    int status;
    tlv_pkt_t *result;
    sigar_sys_info_t sysinfo;
    sigar_mem_t memory;
    core_t *core;

    core = c2->data;

    if ((status = sigar_sys_info_get(core->sigar, &sysinfo)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar sysinfo (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if ((status = sigar_mem_get(core->sigar, &memory)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar memory (%s)\n",
                  sigar_strerror(core->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    tlv_pkt_add_string(result, TLV_TYPE_PLATFORM, sysinfo.name);
    tlv_pkt_add_string(result, TLV_TYPE_VERSION, sysinfo.version);
    tlv_pkt_add_string(result, TLV_TYPE_ARCH, sysinfo.arch);
    tlv_pkt_add_string(result, TLV_TYPE_MACHINE, sysinfo.machine);
    tlv_pkt_add_string(result, TLV_TYPE_VENDOR, sysinfo.vendor);

    tlv_pkt_add_u64(result, TLV_TYPE_RAM_TOTAL, memory.total);
    tlv_pkt_add_u64(result, TLV_TYPE_RAM_USED, memory.used);
    tlv_pkt_add_u32(result, TLV_TYPE_FLAGS, core->flags);

    return result;
}

static tlv_pkt_t *builtin_whoami(c2_t *c2)
{
    tlv_pkt_t *result;

#ifndef __windows__
    struct passwd *pw_entry;

    if ((pw_entry = getpwuid(geteuid())))
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_string(result, TLV_TYPE_STRING, pw_entry->pw_name);
    }
    else
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }
#else
    result = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED);
#endif

    return result;
}

static tlv_pkt_t *builtin_uuid(c2_t *c2)
{
    core_t *core;
    tlv_pkt_t *result;

    core = c2->data;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_UUID, core->uuid);

    return result;
}

static void builtin_enable_security(struct eio_req *request)
{
    int status;
    c2_t *c2;

    c2 = request->data;
    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    crypt_set_key(c2->crypt, c2->crypt->next_key);
    crypt_set_secure(c2->crypt, STAT_SECURE);

    free(c2->crypt->next_key);
}

static void builtin_disable_security(struct eio_req *request)
{
    c2_t *c2;

    c2 = request->data;
    c2_enqueue_tlv(c2, c2->response);

    tlv_pkt_destroy(c2->request);
    tlv_pkt_destroy(c2->response);

    crypt_set_secure(c2->crypt, STAT_NOT_SECURE);
    crypt_set_algo(c2->crypt, ALGO_NONE);
}

static tlv_pkt_t *builtin_unsecure(c2_t *c2)
{
    c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    log_debug("* Disabling security\n");
    eio_custom(builtin_disable_security, 0, NULL, c2);

    return NULL;
}

static tlv_pkt_t *builtin_secure(c2_t *c2)
{
    size_t length;

    int pkey_length;
    int key_length;

    char pkey[4096];
    unsigned char buffer[MBEDTLS_MPI_MAX_SIZE];

    if ((pkey_length = tlv_pkt_get_string(c2->request, TLV_TYPE_PUBLIC_KEY, pkey)) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }
    pkey_length++;

    crypt_set_algo(c2->crypt, ALGO_AES256_CBC);

    if ((key_length = crypt_generate_key(c2->crypt, &c2->crypt->next_key)) < 0)
    {
        goto fail;
    }

    memset(buffer, '\0', MBEDTLS_MPI_MAX_SIZE);
    length = crypt_pkcs_encrypt(c2->crypt->next_key, key_length, (unsigned char *)pkey,
                                pkey_length, buffer);

    if (length <= 0)
    {
        goto fail;
    }

    c2->response = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(c2->response, TLV_TYPE_KEY, buffer, length);

    log_debug("Symmetric key: \n");
    log_hexdump(c2->crypt->next_key, 32);

    log_debug("Symmetric key encrypted with PKCS: \n");
    log_hexdump(buffer, length);

    eio_custom(builtin_enable_security, 0, NULL, c2);
    return NULL;

fail:
    crypt_set_algo(c2->crypt, ALGO_NONE);
    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

void register_builtin_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, BUILTIN_QUIT, builtin_quit);
    api_call_register(api_calls, BUILTIN_ADD_TAB_DISK, builtin_add_tab_disk);
    api_call_register(api_calls, BUILTIN_ADD_TAB_BUFFER, builtin_add_tab_buffer);
    api_call_register(api_calls, BUILTIN_DELETE_TAB, builtin_delete_tab);
    api_call_register(api_calls, BUILTIN_SYSINFO, builtin_sysinfo);
    api_call_register(api_calls, BUILTIN_TIME, builtin_time);
    api_call_register(api_calls, BUILTIN_WHOAMI, builtin_whoami);
    api_call_register(api_calls, BUILTIN_UUID, builtin_uuid);
    api_call_register(api_calls, BUILTIN_SECURE, builtin_secure);
    api_call_register(api_calls, BUILTIN_UNSECURE, builtin_unsecure);
}

#endif
