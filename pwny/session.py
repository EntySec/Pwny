"""
MIT License

Copyright (c) 2020-2022 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import json
import socket

from .plugins import Plugins
from .transfer import Transfer

from hatsploit.lib.loot import Loot
from hatsploit.lib.session import Session
from hatsploit.lib.commands import Commands

from pex.ssl import OpenSSL
from pex.string import String
from pex.proto.channel import ChannelClient


class PwnySession(Session, Plugins, Transfer, OpenSSL, String, ChannelClient):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny session for HatSploit Framework.
    """

    loot = Loot()
    commands = Commands()

    prompt = '%linepwnypreter%end > '
    pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'

    channel = None

    details = {
        'Post': "",
        'Platform': "",
        'Architecture': "",
        'Type': "pwny"
    }

    def open(self, client: socket.socket) -> None:
        """ Open the Pwny session.

        :param socket.socket client: client to open session with
        :return None: None
        """

        client = self.wrap_client(
            client,
            self.loot.random_loot('key'),
            self.loot.random_loot('crt')
        )

        self.channel = self.open_channel(client)

    def close(self) -> None:
        """ Close the Pwny session.

        :return None: None
        """

        self.channel.disconnect()

    def heartbeat(self) -> bool:
        """ Check the Pwny session heartbeat.

        :return bool: True if the Pwny session is alive
        """

        return not self.channel.terminated

    def send_command(self, command: str, output: bool = False) -> str:
        """ Send command to the Pwny session.

        :param str command: command to send
        :param bool output: wait for the output or not
        :return str: command output
        """

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
            output
        )

    def download(self, remote_file: str, local_path: str) -> bool:
        """ Download file from the Pwny session.

        :param str remote_file: file to download
        :param str local_path: path to save downloaded file to
        :return bool: True if download succeed
        """

        return self.pull(
            self.channel,
            remote_file,
            local_path
        )

    def upload(self, local_file: str, remote_path: str) -> bool:
        """ Upload file to the Pwny session.

        :param str local_file: file to upload
        :param str remote_path: path to save uploaded file to
        :return bool: True if upload succeed
        """

        return self.push(
            self.channel,
            local_file,
            remote_path
        )

    def interact(self) -> None:
        """ Interact with the Monhorn session.

        :return None: None
        """

        self.print_empty()

        if self.channel.terminated:
            self.print_warning("Connection terminated.")
            self.close()
            return

        commands = self.commands.load_commands(
            self.pwny + 'commands/' + self.details['Platform'].lower()
        )

        commands.update(
            self.commands.load_commands(
                self.pwny + 'commands/generic'
            )
        )

        plugins = self.import_plugins(
            self.pwny + 'plugins/' + self.details['Platform'].lower()
        )

        for command in commands:
            commands[command].session = self

        while True:
            command = self.input_empty(self.prompt)

            if command:
                if command[0] == 'quit':
                    break

                elif command[0] == 'help':
                    self.print_table("Core Commands", ('Command', 'Description'), *[
                        ('exit', 'Terminate Pwny session.'),
                        ('help', 'Show available commands.'),
                        ('quit', 'Stop interaction.')
                    ])

                    self.commands.show_commands(commands)
                    continue

                if command[0] == 'exit':
                    self.send_command("exit")
                    self.channel.terminated = True

            if self.channel.terminated:
                self.print_warning("Connection terminated.")
                self.close()
                break

            if command:
                if not self.commands.execute_custom_command(cmd, commands, False):
                    self.commands.execute_custom_plugin_command(cmd, plugins)
