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

#ifndef _CALLS_H_
#define _CALLS_H_

#include <api.h>
#include <builtins.h>
#include <process.h>
#include <fs.h>

#ifdef IS_IPHONE
#include <ios/cam.h>
#include <ios/ui.h>
#include <ios/player.h>
#include <ios/locate.h>
#include <ios/gather.h>
#endif

#ifdef IS_MACOS
#include <macos/cam.h>
#include <macos/ui.h>
#endif

void register_api_calls(api_calls_t **api_calls)
{
    register_builtin_api_calls(api_calls);
    register_process_api_calls(api_calls);
    register_fs_api_calls(api_calls);

#ifdef IS_IPHONE
    register_cam_api_calls(api_calls);
    register_ui_api_calls(api_calls);
    register_player_api_calls(api_calls);
    register_locate_api_calls(api_calls);
    register_gather_api_calls(api_calls);
#endif

#ifdef IS_MACOS
    register_cam_api_calls(api_calls);
    register_ui_api_calls(api_calls);
#endif
}

void register_api_pipes(pipes_t **pipes)
{
    register_fs_api_pipes(pipes);
    register_process_api_pipes(pipes);

#ifdef IS_IPHONE
    register_player_api_pipes(pipes);
#endif
}

#endif
