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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>

#include <core.h>
#include <misc.h>
#include <log.h>

#ifdef GC_INUSE
#include <gc.h>
#include <gc/leak_detector.h>
#endif

static void parse_argv(int argc, char *argv[], core_t *core)
{
    int step;
    int index;
    char *short_options;

    struct option long_options[] = {
        {"uri", required_argument, NULL, 'u'},
    };
    short_options = "u:";

    step = 0;
    index = 0;

    optind = 1;
    while ((step = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
    {
        switch (step)
        {
            case 'u':
                core_add_uri(core, optarg);
                break;
            default:
                break;
        }
    }
}

static void parse_options(core_t *core)
{
    size_t argc;
    char **argv;

    static char options[] = "INJECT_OPTIONS"
        "                                                  "
        "                                                  "
        "                                                  "
        "                                                  "
        "                                                  "
        "                                                  "
        "                                                  "
        "                                                  "
        "                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  "
		"                                                  ";

    argc = 0;
    argv = NULL;

    if (strncasecmp(options, "INJECT_OPTIONS", strlen("INJECT_OPTIONS")))
    {
        if ((argv = misc_argv_split(options, argv, &argc)))
        {
            parse_argv(argc, argv, core);
        }
    }
}

int main(int argc, char *argv[])
{
    int sock;
    char *uri;
    core_t *core;

    signal(SIGPIPE, SIG_IGN);
    core = core_create();

    if (core == NULL)
    {
        log_debug("* Failed to initialize core\n");
        return 1;
    }

    core_setup(core);

    if (strcmp(argv[0], "p") == 0)
    {
        sock = (int)((long *)argv)[1];

        if (asprintf(&uri, "sock://%d", sock) > 0)
        {
            core_add_uri(core, uri);
            free(uri);
        }
    }
    else
    {
        parse_argv(argc, argv, core);
    }

    parse_options(core);
    core_start(core);

    core_destroy(core);

    return 0;
}