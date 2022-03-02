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

from hatsploit.utils.fs import FSTools
from hatsploit.utils.ssl import SSLTools
from hatsploit.utils.string import StringTools
from hatsploit.utils.channel import ChannelClient


class PwnySession(Session, FSTools, SSLTools, StringTools, ChannelClient):
    commands = Commands()

    prompt = '%linepwnypreter%end > '
    pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/commands/'

    channel = None

    details = {
        'Post': "",
        'Platform': "",
        'Architecture': "",
        'Type': "pwny"
    }

    def open(self, client):
        client = self.wrap_client(client)
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

    def download(self, remote_file, local_path):
        request = json.dumps({
            'cmd': "download",
            'args': remote_file,
            'token': ''
        })

        data = self.channel.send_command(request, True)

        if data == 'file':
            exists, is_dir = self.exists(local_path)
            if exists:
                if is_dir:
                    local_path = local_path + '/' + os.path.split(remote_file)[1]

                self.print_process(f"Downloading {remote_file}...")

                token = self.random_string(8)
                self.channel.send_command(token, False)

                while True:
                    chunk = self.channel.read(1024)
                    if token in chunk:
                        token_index = chunk.index(token)
                        token_size = len(token)

                        self.print_process(f"Saving to {local_path}...")
                        file.write(chunk[:token_index])

                        break

                    file.write(chunk)

                self.print_success(f"Saved to {local_path}!")
                file.close()

                return True

        elif data == 'directory':
            self.print_error(f"Remote file: {remote_file}: is a directory!")
        else:
            self.print_error(f"Remote file: {remote_file}: does not exist!")

        return False

    def upload(self, local_file, remote_path):
        return None

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

        commands = commands + 'generic'
        generic = self.commands.load_commands(commands)

        for command in generic:
            generic[command].session = self

        self.print_information(f"Loaded {len(pwny) + len(generic)} commands.")
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

                    self.commands.show_commands(generic)
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
                if not self.commands.execute_custom_command(commands, generic, False):
                    self.commands.execute_custom_command(commands, pwny)
