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

/*! \file core.h
 *  \brief control core entry point to a main event loop
 */

#ifndef _CORE_H_
#define _CORE_H_

#include <c2.h>
#include <tlv.h>
#include <ev.h>

#define CORE_EV_FLAGS EVFLAG_NOENV | EVBACKEND_SELECT | EVFLAG_FORKCHECK

/*! \struct core_t
 *  \brief core instance structure
 *
 *  \var core_t::c2
 *  hash table of C2 instances
 *  \var core_t::loop
 *  event loop
 */

typedef struct
{
    c2_t *c2;

    struct ev_loop *loop;
} core_t;

/*! \fn core_t *core_create(c2_t *c2)
 *  \brief create a core instance and return it
 *
 *  \param c2 hash table containing C2 instances
 *  \return core instance
 */

core_t *core_create(c2_t *c2);

/*! \fn int core_start(core_t *core)
 *  \brief start the main event loop on core
 *
 *  \param core core instance
 *  \return event loop error code
 */

int core_start(core_t *core);

/*! \fn void core_destroy(core_t *core)
 *  \brief Destroy core instance freeing it
 *
 *  \param core core instance to destroy
 */

void core_destroy(core_t *core);

#endif