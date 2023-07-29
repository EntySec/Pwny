"""
MIT License

Copyright (c) 2020-2023 EntySec

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

from .plugins import Plugins

from badges import Badges, Tables

from hatsploit.lib.runtime import Runtime
from hatsploit.lib.session import Session
from hatsploit.lib.commands import Commands
from hatsploit.lib.handler import Handler

from pex.fs import FS


class Console(Plugins, Tables, Badges, Runtime, Commands, FS):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny main console.
    """

    def __init__(self):
        super().__init__()

        self.prompt = '%linepwny%end > '

        self.core_commands = [
            ('exit', 'Terminate Pwny session.'),
            ('help', 'Show available commands.'),
            ('load', 'Load Pwny plugin.'),
            ('migrate', 'Migrate Pwny to PID.'),
            ('plugins', 'List Pwny plugins.'),
            ('quit', 'Stop interaction.'),
            ('unload', 'Unload Pwny plugin.')
        ]

        self.commands = {}

        self.handler = Handler()

    def check_session(self, session: Session) -> bool:
        """ Check is session alive.

        :param Session session: session to check
        :return bool: True if session is alive
        """

        if session.channel.terminated:
            self.print_warning("Connection terminated.")
            session.close()

            return False
        return True

    def start_pwny(self, session: Session) -> None:
        """ Start Pwny.

        :param Session session: session to start Pwny for
        :return None: None
        """

        commands = session.pwny_commands + session.details['Platform'].lower()
        exists, is_dir = self.exists(commands)

        if exists and is_dir:
            self.commands.update(
                self.load_commands(commands)
            )

        commands = session.pwny_commands + 'generic'
        exists, is_dir = self.exists(commands)

        if exists and is_dir:
            self.commands.update(
                self.load_commands(commands)
            )

        for command in self.commands:
            self.commands[command].session = session

        plugins = session.pwny_plugins + session.details['Platform'].lower()
        exists, is_dir = self.exists(plugins)

        if exists and is_dir:
            self.import_plugins(plugins, session)

        plugins = session.pwny_plugins + 'generic'
        exists, is_dir = self.exists(plugins)

        if exists and is_dir:
            self.import_plugins(plugins, session)

    def pwny_console(self, session: Session) -> None:
        """ Start Pwny console.

        :param Session session: session to start Pwny console for
        :return None: None
        """

        if self.check_session(session):
            while True:
                result = self.catch(self.pwny_shell, [session])
                if result is not Exception and result:
                    break

    def pwny_shell(self, session: Session) -> bool:
        """ Start Pwny shell.

        :param Session session: session to start Pwny shell for
        :return bool: True if Pwny shell completed
        """

        command = self.input_empty(self.prompt)

        if command:
            if command[0] == 'quit':
                return True

            elif command[0] == 'load':
                if len(command) < 2:
                    self.print_usage("load <plugin>")
                else:
                    self.load_plugin(command[1])

            elif command[0] == 'unload':
                if len(command) < 2:
                    self.print_usage("unload <plugin>")
                else:
                    self.unload_plugin(command[1])

            elif command[0] == 'help':
                self.print_table("Core Commands", ('Command', 'Description'),
                                 *self.core_commands)

                self.show_commands(self.commands)

                for plugin in self.loaded_plugins:
                    loaded_plugin = self.loaded_plugins[plugin]

                    if hasattr(loaded_plugin, "commands"):
                        commands_data = {}
                        headers = ("Command", "Description")
                        commands = loaded_plugin.commands

                        for label in sorted(commands):
                            commands_data[label] = []
                            for command in sorted(loaded_plugin.commands[label]):
                                commands_data[label].append(
                                    (command, commands[label][command]['Description']))

                        for label in sorted(commands_data):
                            self.print_table(label.title() + " Commands", headers, *commands_data[label])

            elif command[0] == 'plugins':
                self.show_plugins()

            elif command[0] == 'exit':
                session.send_command("exit")
                session.channel.terminated = True
                return True

            else:
                self.check_session(session)

                if not self.execute_custom_command(command, self.commands, False):
                    self.execute_custom_plugin_command(command, self.loaded_plugins)

        return False
