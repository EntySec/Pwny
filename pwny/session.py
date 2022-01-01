#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import os
import json

from hatsploit.lib.session import Session
from hatsploit.lib.commands import Commands

from hatsploit.utils.string import StringTools
from hatsploit.utils.channel import ChannelClient


class PwnySession(Session, StringTools, ChannelClient):
    commands = Commands()

    prompt = '%linepwny%end > '
    pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/commands/'

    channel = None

    details = {
        'Post': "",
        'Platform': "",
        'Architecture': "",
        'Type': "pwny"
    }

    def open(self, client):
        self.channel = self.open_channel(client)

    def close(self):
        self.channel.disconnect()

    def heartbeat(self):
        return not self.channel.terminated

    def send_command(self, command, output=False, decode=True):
        args = ''
        token = self.random_string(8)
        commands = self.format_commands(command)

        if len(commands) > 1:
            args = ' '.join(commands[1:])

        command_data = json.dumps({
            'cmd': commands[0],
            'args': args,
            'token': token
        })

        return self.channel.send_token_command(
            command_data,
            token,
            output,
            decode
        )

    def interact(self):
        self.print_empty()

        if self.channel.terminated:
            self.print_warning("Connection terminated.")
            self.close()
            return

        self.print_process("Loading Pwny commands...")
        commands = self.pwny + self.details['Platform'].lower()

        pwny = self.commands.load_commands(commands)
        for command in pwny:
            pwny[command].session = self

        self.print_information(f"Loaded {len(pwny)} commands.")
        self.print_empty()

        while True:
            commands = self.input_empty(self.prompt)

            if commands:
                if commands[0] == 'quit':
                    break

                elif commands[0] == 'help':
                    self.print_table("Core Commands", ('Command', 'Description'), *[
                        ('exit', 'Terminate Pwny session.'),
                        ('help', 'Show available commands.'),
                        ('quit', 'Stop interaction.')
                    ])

                    self.commands.show_commands(pwny)
                    continue

                if commands[0] == 'exit':
                    self.send_command("exit")
                    self.channel.terminated = True

            if self.channel.terminated:
                self.print_warning("Connection terminated.")
                self.close()
                break

            if commands:
                self.commands.execute_custom_command(commands, pwny)
