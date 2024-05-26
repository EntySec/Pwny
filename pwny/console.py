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

import os
import io
import cmd

from pwny.types import *
from pwny.api import *
from pwny.plugins import Plugins
from pwny.migrate import Migrate
from pwny.tips import Tips

from contextlib import redirect_stdout

from colorscript import ColorScript
from badges import Badges, Tables

from pex.platform.types import *
from pex.arch.types import *

from hatsploit.lib.runtime import Runtime
from hatsploit.lib.session import Session
from hatsploit.lib.commands import Commands
from hatsploit.lib.handler import Handler
from hatsploit.lib.show import Show

from pex.fs import FS


class Console(cmd.Cmd):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny main console.
    """

    def __init__(self, prompt: str = '%removepwny:%line$dir%end %blue$user%end$prompt ') -> None:
        """ Initialize Pwny console.

        :param str prompt: prompt line (supports ColorScript)
        :return None: None
        """

        super().__init__()
        cmd.Cmd.__init__(self)

        self.version = '1.0.0'

        self.scheme = prompt
        self.prompt = prompt

        self.motd = f"""%end
Pwny interactive shell %greenv{self.version}%end
Running as %blue$user%end on %line$dir%end
"""

        self.plugins = Plugins()
        self.commands = Commands()
        self.show = Show()

        self.runtime = Runtime()

        self.badges = Badges()
        self.tables = Tables()
        self.fs = FS()

        self.core_commands = sorted([
            ('set', 'Set environment variable.'),
            ('unset', 'Delete environment variable.'),
            ('env', 'List environment variables.'),
            ('exit', 'Terminate Pwny session.'),
            ('help', 'Show available commands.'),
            ('load', 'Load Pwny plugin.'),
            ('plugins', 'List Pwny plugins.'),
            ('quit', 'Stop interaction.'),
            ('prompt', 'Set prompt message.'),
            ('exec', 'Execute path.'),
            ('unload', 'Unload Pwny plugin.')
        ])

        self.search = {
            OS_LINUX: [
                '/usr/local/sbin',
                '/usr/local/bin',
                '/usr/sbin',
                '/usr/bin',
                '/sbin',
                '/bin'
            ],
            OS_MACOS: [
                '/opt/homebrew/sbin',
                '/opt/homebrew/bin',
                '/usr/local/sbin',
                '/usr/local/bin',
                '/usr/sbin',
                '/usr/bin',
                '/sbin',
                '/bin'
            ],
            OS_IPHONE: [
                '/var/lib/filza/bins/bin',
                '/usr/local/sbin',
                '/usr/local/bin',
                '/usr/sbin',
                '/usr/bin',
                '/sbin',
                '/bin'
            ]
        }

        self.custom_commands = {}

        self.handler = Handler()
        self.session = None
        self.env = {}

    def get_env(self, name: str) -> str:
        """ Get environment variable.

        :param str name: variable name
        :return str: variable value if exists else empty string
        """

        return self.env.get(name.upper(), '')

    def set_env(self, name: str, value: str) -> None:
        """ Set environment variable.

        :param str name: variable name
        :param str value: variable value
        :return None: None
        """

        if value is None:
            self.env.pop(name.upper(), value)
            return

        self.env[name.upper()] = str(value)

    def set_prompt(self, prompt: str) -> None:
        """ Set prompt.

        :param str prompt: prompt to set
        :return None: None
        """

        self.scheme = prompt
        self.prompt = self.parse_message(prompt)

    def set_motd(self, message: str) -> None:
        """ Set message of the day.

        :param str message: message to set
        :return None: None
        """

        self.motd = self.parse_message(message)

    def whoami(self) -> str:
        """ Get current session username.

        :return str: username
        """

        self.check_session()

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

        self.check_session()

        result = self.session.send_command(
            tag=FS_GETWD
        )

        if result.get_int(TLV_TYPE_STATUS) == TLV_STATUS_SUCCESS:
            return result.get_string(TLV_TYPE_PATH)

        return '???'

    def parse_message(self, message: str) -> str:
        """ Parse message.

        :param str message: message to parse
        :return str: parsed message
        """

        message = message.strip("'\"")
        message = ColorScript().parse_input(message)

        if '$dir' in message:
            path = self.pwd()

            if len(path) > 32:
                paths = path.split('/')
                pointer = 0

                while len(path) > 32:
                    paths = paths[pointer:]
                    if paths:
                        path = os.path.join(*paths)
                    pointer += 1

                path = '*/' + path

            message = message.replace('$dir', path)

        if '$user' in message:
            message = message.replace('$user', self.whoami())

        if '$prompt' in message:
            message = message.replace('$prompt', '#' if self.whoami() == 'root' else '$')

        return message

    def do_help(self, _) -> None:
        """ Show available commands.

        :return None: None
        """

        self.tables.print_table("Core Commands", ('Command', 'Description'),
                                *self.core_commands)
        self.commands.show_commands(self.custom_commands)
        self.show.show_plugin_commands(self.plugins.loaded_plugins)

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

    def do_exec(self, line: str) -> None:
        """ Execute path.

        :param str line: path with arguments
        :return None: None
        """

        line = line.split()

        if len(line) < 1:
            self.badges.print_usage("exec <path>")
            return

        self.check_session()

        if len(line) >= 2:
            self.session.spawn(line[0], line[1:])
            return

        self.session.spawn(line[0], [])

    def do_set(self, line: str) -> None:
        """ Set environment variable.

        :param str line: variable name and value
        :return None: None
        """

        line = line.split()

        if len(line) < 2:
            self.badges.print_usage("set <name> <value>")
            return

        self.set_env(line[0], line[1])

    def do_unset(self, name: str) -> None:
        """ Delete environment variable.

        :param str name: variable name
        :return None: None
        """

        if not name:
            self.badges.print_usage("unset <name>")
            return

        self.set_env(name, None)

    def do_env(self, _) -> None:
        """ List environment variables.

        :return None: None
        """

        env_data = []

        for name in self.env:
            env_data.append((name, self.env[name]))

        if not env_data:
            self.badges.print_warning("No environment available.")
            return

        self.tables.print_table("Environment Variables", ('Name', 'Value'),
                                *env_data)

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

        self.check_session()

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

        self.check_session()
        command = line.split()

        if self.commands.execute_custom_command(
                command, self.custom_commands, False):
            return

        if self.commands.execute_custom_plugin_command(
                command, self.plugins.loaded_plugins, False):
            return

        search = self.get_env('PATH').split(':')

        if len(command) >= 2:
            status = self.session.spawn(
                command[0], command[1:], search=search)
        else:
            status = self.session.spawn(
                command[0], [], search=search)

        if not status:
            self.badges.print_error(f"Unrecognized command: {command[0]}!")

    def emptyline(self) -> None:
        """ Do something on empty line.

        :return None: None
        """

        pass

    def precmd(self, line: str) -> str:
        """ Do something before processing commands.

        :param str line: commands
        :return str: commands
        """

        for key, item in self.env.items():
            line = line.replace(f'${key}', str(item))

        return line

    def postcmd(self, stop: str, _) -> str:
        """ Do something after each command.

        :param str stop: stop
        :return str: continue
        """

        self.set_prompt(self.scheme)
        return stop

    def check_session(self) -> None:
        """ Check is session alive.

        :return None: None
        :raises RuntimeError: with trailing error message
        :raises RuntimeWarning: with trailing warning message
        """

        if not self.session:
            raise RuntimeError(f"Session is dead ({self.session.reason})!")

        if self.session.terminated:
            self.session.close()
            raise RuntimeWarning(f"Connection terminated ({self.session.reason}).")

    def load_commands(self, path: str) -> None:
        """ Load custom Pwny commands.

        :param str path: commands path
        :return None: None
        """

        self.check_session()

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

        self.check_session()

        exists, is_dir = self.fs.exists(path)

        if exists and is_dir:
            self.plugins.import_plugins(path, self.session)

    def setup_env(self) -> None:
        """ Set up environment.

        :return None: None
        """

        self.check_session()

        self.set_env('PATH', ':'.join(
            self.search.get(self.session.details['Platform'], [])
        ))

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

        self.setup_env()

    def pwny_exec(self, command: str) -> str:
        """ Execute single Pwny command.

        :param str command: command to execute (with arguments)
        :return str: command output
        """

        self.check_session()

        with io.StringIO() as buffer, redirect_stdout(buffer):
            self.badges.set_less(False)
            self.onecmd(command)
            self.badges.set_less(True)
            return buffer.getvalue()

    def pwny_console(self) -> None:
        """ Start Pwny console.

        :return None: None
        """

        self.set_prompt(self.prompt)
        self.set_motd(self.motd)

        if self.motd:
            self.badges.print_empty(self.motd)

        Tips(self.session).print_random_tip()

        while True:
            result = self.runtime.catch(self.pwny_shell)

            if result is not Exception and result:
                break

    def pwny_shell(self) -> bool:
        """ Start Pwny shell.

        :return bool: True to exit
        """

        try:
            self.cmdloop()

        except (EOFError, KeyboardInterrupt):
            self.badges.print_empty(end='')
            return True

        return False
