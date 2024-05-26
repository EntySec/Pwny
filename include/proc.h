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

/*! \file proc.h
 *  \brief brings procedures to manage system processes
 */

#ifndef _PROC_H_
#define _PROC_H_

#include <c2.h>

#include <sigar.h>

/*! \fn int proc_kill(sigar_t *sigar, sigar_pid_t pid)
 *  \brief kill process by ID
 *
 *  \param sigar sigar instance
 *  \param pid process ID
 *  \return error code
 */

int proc_kill(sigar_t *sigar, sigar_pid_t pid);

/*! \fn sigar_pid_t proc_find(sigar_t *sigar, const char *name)
 *  \brief get process ID by process name
 *
 *  \param sigar sigar instance
 *  \param name process name
 *  \return process ID
 */

sigar_pid_t proc_find(sigar_t *sigar, const char *name);

#endif