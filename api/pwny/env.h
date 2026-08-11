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

#ifndef _ENV_H_
#define _ENV_H_

#include <stdlib.h>
#include <string.h>

#include <pwny/tlv.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv_types.h>
#include <pwny/log.h>

extern char **environ;

#define ENV_BASE 18

#define ENV_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       ENV_BASE, \
                       API_CALL)
#define ENV_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       ENV_BASE, \
                       API_CALL + 1)
#define ENV_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       ENV_BASE, \
                       API_CALL + 2)
#define ENV_UNSET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       ENV_BASE, \
                       API_CALL + 3)

#define TLV_TYPE_ENV_KEY   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, ENV_BASE, API_TYPE)
#define TLV_TYPE_ENV_VALUE TLV_TYPE_CUSTOM(TLV_TYPE_STRING, ENV_BASE, API_TYPE + 1)
#define TLV_TYPE_ENV_GROUP TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, ENV_BASE, API_TYPE)

static tlv_pkt_t *env_list(c2_t *c2)
{
    tlv_pkt_t *result;
    tlv_pkt_t *entry;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    char **env;

    for (env = environ; *env != NULL; env++)
    {
        char *eq = strchr(*env, '=');
        if (eq == NULL || eq == *env)
        {
            continue;
        }

        entry = tlv_pkt_create();

        {
            size_t key_len = eq - *env;
            char key_buf[256];
            if (key_len >= sizeof(key_buf))
                key_len = sizeof(key_buf) - 1;
            memcpy(key_buf, *env, key_len);
            key_buf[key_len] = '\0';
            tlv_pkt_add_string(entry, TLV_TYPE_ENV_KEY, key_buf);
        }

        tlv_pkt_add_string(entry, TLV_TYPE_ENV_VALUE, eq + 1);
        tlv_pkt_add_tlv(result, TLV_TYPE_ENV_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    return result;
}

static tlv_pkt_t *env_get(c2_t *c2)
{
    char key[256];
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ENV_KEY, key) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    char *value;

    value = getenv(key);
    if (value == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_ENV_VALUE, value);

    return result;
}

static tlv_pkt_t *env_set(c2_t *c2)
{
    char key[256];
    char value[32768];

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ENV_KEY, key) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ENV_VALUE, value) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (setenv(key, value, 1) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *env_unset(c2_t *c2)
{
    char key[256];

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ENV_KEY, key) <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (unsetenv(key) != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

void register_env_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, ENV_LIST, env_list);
    api_call_register(api_calls, ENV_GET, env_get);
    api_call_register(api_calls, ENV_SET, env_set);
    api_call_register(api_calls, ENV_UNSET, env_unset);
}

#endif
