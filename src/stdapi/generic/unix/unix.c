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

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <sys/types.h>
#include <sys/utsname.h>

#ifdef SYSCALL_REBOOT
#include <linux/reboot.h>
#define reboot(arg) reboot(0xfee1dead, 0x28121969, arg, NULL)
#else
#include <sys/reboot.h>
#endif

#include "channel.h"

static char *get_time_str(char *format)
{
    static char time_stamp[128];
    time_t time_int;

    time(&time_int);
    strftime(time_stamp, sizeof(time_stamp), format, localtime(&time_int));
    return time_stamp;
}

void cmd_time(int channel)
{
    char time[64];
    sprintf(time, "%s\n", get_time_str("%a %b %d %H:%M:%S %Z %Y"));
    send_channel(channel, time);
}
