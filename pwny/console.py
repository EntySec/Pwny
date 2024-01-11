"""
MIT License

Copyright (c) 2020-2024 EntySec

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

import cmd

from pwny.types import *
from pwny.api import *
from pwny.plugins import Plugins
from pwny.migrate import Migrate

from hatsploit.lib.session import Session

from colorscript import ColorScript
from badges import Badges, Tables

from pex.platform.types import *
from pex.arch.types import *

from hatsploit.lib.runtime import Runtime
from hatsploit.lib.commands import Commands
from hatsploit.lib.handler import Handler

from pex.fs import FS


class Console(cmd.Cmd):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny main console.
    """

    def __init__(self, prompt: str = '%linepwny%end > ') -> None:
        """ Initialize Pwny console.

        :param str prompt: prompt line (supports ColorScript)
        :return None: None
        """

        super().__init__()
        cmd.Cmd.__init__(self)

        self.scheme = prompt
        self.prompt = self.parse_prompt(prompt)

        self.plugins = Plugins()
        self.commands = Commands()

        self.runtime = Runtime()

        self.badges = Badges()
        self.tables = Tables()
        self.fs = FS()

        self.core_commands = [
            ('exit', 'Terminate Pwny session.'),
            ('help', 'Show available commands.'),
            ('load', 'Load Pwny plugin.'),
            ('plugins', 'List Pwny plugins.'),
            ('quit', 'Stop interaction.'),
            ('prompt', 'Set prompt.'),
            ('unload', 'Unload Pwny plugin.')
        ]

        self.custom_commands = {}

        self.handler = Handler()
        self.session = None

    def set_prompt(self, prompt: str) -> None:
        """ Set prompt.

        :param str prompt: prompt to set
        :return None: None
        """

        self.scheme = prompt
        self.prompt = self.parse_prompt(prompt)

    def whoami(self) -> str:
        """ Get current session username.

        :return str: username
        """

        if self.session:
            result = self.session.send_command(
                tag=BUILTIN_WHOAMI
            )

            if result.get_int(TLV_TYPE_STATUS) == TLV_STATUS_SUCCESS:
                return result.get_string(TLV_TYPE_STRING)

        return '???'

    def pwd(self) -> str:
        """ Get current session working directory.

        :return str: working directory
        """

        if self.session:
            result = self.session.send_command(
                tag=FS_GETWD
            )

            if result.get_int(TLV_TYPE_STATUS) == TLV_STATUS_SUCCESS:
                return result.get_string(TLV_TYPE_PATH)

        return '???'

    def parse_prompt(self, prompt: str) -> str:
        """ Parse prompt.

        :param str prompt: prompt to parse
        :return str: parsed prompt
        """

        prompt = prompt.strip("'\"")
        prompt = ColorScript().parse_input(prompt)

        if '$dir' in prompt:
            prompt = prompt.replace('$dir', self.pwd())

        if '$user' in prompt:
            prompt = prompt.replace('$user', self.whoami())

        if '$prompt' in prompt:
            prompt = prompt.replace('$prompt', '#' if self.whoami() == 'root' else '$')

        return prompt

    def do_help(self, _) -> None:
        """ Show available commands.

        :return None: None
        """

        self.tables.print_table("Core Commands", ('Command', 'Description'),
                                *self.core_commands)
        self.commands.show_commands(self.custom_commands)

        for plugin in self.plugins.loaded_plugins:
            loaded_plugin = self.plugins.loaded_plugins[plugin]

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
                    self.tables.print_table(label.title() + " Commands", headers, *commands_data[label])

    def do_plugins(self, _) -> None:
        """ Show available plugins.

        :return None: None
        """

        self.plugins.show_plugins()

    def do_load(self, plugin: str) -> None:
        """ Load plugin by name.

        :param str plugin: plugin name
        :return None: None
        """

        if not plugin:
            self.badges.print_usage("load <name>")
            return

        self.plugins.load_plugin(plugin)

    def do_unload(self, plugin: str) -> None:
        """ Unload plugin by name.

        :param str plugin: plugin name
        :return None: None
        """

        if not plugin:
            self.badges.print_usage("unload <name>")
            return

        self.plugins.unload_plugin(plugin)

    def do_prompt(self, prompt: str) -> None:
        """ Set current prompt line.

        :param str prompt: prompt line (supports ColorScript)
        :return None: None
        """

        if not prompt:
            self.badges.print_usage("prompt <line>")
            return

        self.set_prompt(prompt)

    def do_exit(self, _) -> None:
        """ Exit Pwny and terminate connection.

        :return None: None
        :raises EOFError: EOF error
        """

        self.session.send_command(
            tag=BUILTIN_QUIT
        )
        self.session.terminated = True

        raise EOFError

    def do_quit(self, _) -> None:
        """ Exit Pwny.

        :return None: None
        :raises EOFError: EOF error
        """

        raise EOFError

    def do_clear(self, _) -> None:
        """ Clear terminal window.

        :return None: None
        """

        self.badges.print_empty('%clear', end='')

    def do_EOF(self, _):
        """ Catch EOF.

        :return None: None
        :raises EOFError: EOF error
        """

        raise EOFError

    def default(self, line: str) -> None:
        """ Default unrecognized command handler.

        :param str line: line sent
        :return None: None
        """

        if self.check_session():
            command = line.split()

            if not self.commands.execute_custom_command(
                    command, self.custom_commands, False):
                self.commands.execute_custom_plugin_command(
                    command, self.plugins.loaded_plugins)

    def emptyline(self) -> None:
        """ Do something on empty line.

        :return None: None
        """

        pass

    def postcmd(self, stop: str, _) -> str:
        """ Do something after each command.

        :param str stop: stop
        :return str: continue
        """

        self.set_prompt(self.scheme)
        return stop

    def check_session(self) -> bool:
        """ Check is session alive.

        :return bool: True if session is alive
        """

        if not self.session:
            self.badges.print_error("Session is dead (reason unknown)")
            return False

        if self.session.terminated:
            self.badges.print_warning("Connection terminated.")
            self.session.close()

            return False
        return True

    def load_commands(self, path: str) -> None:
        """ Load custom Pwny commands.

        :param str path: commands path
        :return None: None
        """

        exists, is_dir = self.fs.exists(path)

        if exists and is_dir:
            self.custom_commands.update(
                self.commands.load_commands(path)
            )

        for command in self.custom_commands:
            self.custom_commands[command].session = self.session

    def load_plugins(self, path: str) -> None:
        """ Load custom Pwny plugins.

        :param str path: plugins path
        :return None: None
        """

        exists, is_dir = self.fs.exists(path)

        if exists and is_dir:
            self.plugins.import_plugins(path, self.session)

    def start_pwny(self, session: Session) -> None:
        """ Start Pwny.

        :param Session session: session to start Pwny for
        :return None: None
        """

        self.session = session

        self.load_commands(session.pwny_commands + str(
            session.details['Platform']).lower())
        self.load_commands(session.pwny_commands + 'generic')

        self.load_plugins(session.pwny_plugins + str(
            session.details['Platform']).lower())
        self.load_plugins(session.pwny_plugins + 'generic')

    def pwny_console(self) -> None:
        """ Start Pwny console.

        :return None: None
        """

        while True:
            result = self.runtime.catch(self.pwny_shell)

            if result is not Exception and result:
                break

    def pwny_shell(self) -> bool:
        """ Start Pwny shell.

        :return bool: True to exit
        """

        try:
            cmd.Cmd.cmdloop(self)

        except (EOFError, KeyboardInterrupt):
            self.badges.print_empty(end='')
            return True

        return False
