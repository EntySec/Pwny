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
#include <stdarg.h>

#include <log.h>

void log_debug(const char *fmt __attribute__((unused)), ...)
{
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);

    vfprintf(stderr, fmt, args);

    va_end(args);
#endif
}

void log_hexdump(const void *data, size_t size)
{
#ifdef DEBUG
    char ascii[17];
    size_t iter;
    size_t pointer;

    ascii[16] = '\0';

    for (iter = 0; iter < size; iter++)
    {
        log_debug("%02X ", ((unsigned char*)data)[iter]);

        if (((unsigned char*)data)[iter] >= ' ' && ((unsigned char*)data)[iter] <= '~')
        {
            ascii[iter % 16] = ((unsigned char*)data)[iter];
        }
        else
        {
            ascii[iter % 16] = '.';
        }

        if ((iter + 1) % 8 == 0 || iter + 1 == size)
        {
            log_debug(" ");

            if ((iter + 1) % 16 == 0)
            {
                log_debug("|  %s \n", ascii);
            }
            else if (iter + 1 == size)
            {
                ascii[(iter + 1) % 16] = '\0';

                if ((iter + 1) % 16 <= 8)
                {
                    log_debug(" ");
                }

                for (pointer = (iter + 1) % 16; pointer < 16; pointer++)
                {
                    log_debug("   ");
                }

                log_debug("|  %s \n", ascii);
            }
        }
    }
#endif
}
