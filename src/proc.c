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

#include <c2.h>
#include <proc.h>
#include <log.h>

#include <stdlib.h>
#include <string.h>
#include <sigar.h>

sigar_pid_t proc_find(sigar_t *sigar, const char *name)
{
    int iter;
    int status;

    sigar_pid_t proc_pid;
    sigar_proc_state_t proc_state;
    sigar_proc_list_t proc_list;

    if ((status = sigar_proc_list_get(sigar, &proc_list)) != SIGAR_OK)
    {
        log_debug("* Cannot build process tree\n");
        return -1;
    }

    for (iter = 0; iter < proc_list.number; iter++)
    {
        proc_pid = proc_list.data[iter];

        if ((status = sigar_proc_state_get(sigar, proc_pid, &proc_state)) != SIGAR_OK)
        {
            continue;
        }

        if (!strcmp(proc_state.name, name))
        {
            log_debug("* Found (%s) on PID (%d)\n", name, proc_pid);

            sigar_proc_list_destroy(sigar, &proc_list);
            return proc_pid;
        }
    }

    sigar_proc_list_destroy(sigar, &proc_list);
    return -1;
}

int proc_kill(sigar_t *sigar, sigar_pid_t pid)
{
    int status;

    if ((status = sigar_proc_kill(pid, 9)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar process kill (%d) (%s)\n",
                  pid, sigar_strerror(sigar, status));
        return -1;
    }

    return 0;
}