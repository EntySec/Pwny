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
#include <sys/stat.h>
#include <sys/utsname.h>

#include <openssl/ssl.h>

#include "tools.h"
#include "channel.h"

#define BUFFER_SIZE 1024

static char *get_time_str(char *format)
{
    static char time_stamp[128];
    time_t time_int;

    time(&time_int);
    strftime(time_stamp, sizeof(time_stamp), format, localtime(&time_int));
    return time_stamp;
}

void cmd_time(SSL *channel)
{
    char time[2048];
    sprintf(time, "%s\n", get_time_str("%a %b %d %H:%M:%S %Z %Y"));
    send_channel(channel, time);
}

void cmd_download(SSL *channel, char *args)
{
    struct stat path_s;
    if (stat(args, &path_s) != 0) {
        send_channel(channel, "incorrect");
        return;
    }

    if (S_ISDIR(path_s.st_mode)) {
        send_channel(channel, "directory");
        return;
    }

    send_channel(channel, "file");
    char *token = read_channel(channel);

    FILE *file;
    int length;
    char buffer[BUFFER_SIZE];

    file = fopen(args, "rb");

    if (file == NULL)
        send_channel(channel, token);

    while ((length = fread(buffer, sizeof(char), 1, file)) > 0) {
        send_channel(channel, buffer);
        memset(buffer, 0, BUFFER_SIZE);
    }

    send_channel(channel, token);
    fclose(file);
}

void cmd_upload(SSL *channel, char *args)
{
    struct stat path_s;
    if (stat(args, &path_s) != 0) {
        send_channel(channel, "file");
    } else {
        send_channel(channel, "directory");
        args = read_channel(channel);
    }

    char *token = read_channel(channel);
    char *data;

    FILE *file;
    file = fopen(args, "wb");

    if (file == NULL) {
        send_channel(channel, "error");
        return;
    } else
        send_channel(channel, "success");

    while (1) {
        data = read_channel(channel);

        if (strstr(data, token)) {
            data = remove_last(data, strlen(token));
            fwrite(data, sizeof(char), 1, file);
            break;
        }

        fwrite(data, sizeof(char), 1, file);
    }

    fclose(file);
}
