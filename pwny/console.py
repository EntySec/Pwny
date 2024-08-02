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

from pwny.api import *
from pwny.types import *

from pex.arch import *
from pex.platform import *

from pwny.plugins import Plugins
from pwny.migrate import Migrate
from pwny.tips import Tips

from contextlib import redirect_stdout

from colorscript import ColorScript
from badges.cmd import Cmd

from hatsploit.lib.core.session import Session

from pex.fs import FS


class Console(Cmd, FS):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny main console.
    """

    def __init__(self, session: Session,
                 prompt: str = 'pwny:%line$dir%end %blue$user%end$prompt ') -> None:
        """ Initialize Pwny console.

        :param Session session: session object
        :param str prompt: prompt line (supports ColorScript)
        :return None: None
        """

        self.session = session

        super().__init__(
            prompt=prompt,
            session=session
        )

        self.version = '1.0.0'

        self.scheme = prompt
        self.prompt = prompt

        self.motd = f"""%end
Pwny interactive shell %greenv{self.version}%end
Running as %blue$user%end on %line$dir%end
"""

        self.plugins = Plugins()

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
        message = ColorScript().parse(message)

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

    def do_plugins(self, _) -> None:
        """ Show available plugins.

        :return None: None
        """

        self.plugins.show_plugins()

    def do_load(self, args: list) -> None:
        """ Load plugin by name.

        :param list args: arguments list
        :return None: None
        """

        if len(args) < 2:
            self.print_usage("load <name>")
            return

        self.plugins.load_plugin(args[1])

        plugin = self.plugins.loaded_plugins[args[1]]
        commands = {}

        for command in plugin.commands:
            commands[command] = plugin.commands[command]
            commands[command]['Method'] = getattr(plugin, command)
            commands[command]['Category'] = plugin.info['Plugin']

        self.add_external(commands)

    def do_unload(self, args: list) -> None:
        """ Unload plugin by name.

        :param list args: arguments list
        :return None: None
        """

        if len(args) < 2:
            self.print_usage("unload <name>")
            return

        plugin = self.plugins.loaded_plugins[args[1]]

        for command in plugin.commands:
            self.delete_external(command)

        self.plugins.unload_plugin(args[1])

    def do_exec(self, args: list) -> None:
        """ Execute path.

        :param list args: arguments list
        :return None: None
        """

        if len(args) < 2:
            self.print_usage("exec <path>")
            return

        self.check_session()

        if len(args) >= 2:
            self.session.spawn(args[1], line[2:])
            return

        self.session.spawn(args[1], [])

    def do_set(self, args: list) -> None:
        """ Set environment variable.

        :param list args: arguments list
        :return None: None
        """

        if len(args) < 3:
            self.print_usage("set <name> <value>")
            return

        self.set_env(args[1], args[2])

    def do_unset(self, args: list) -> None:
        """ Delete environment variable.

        :param list args: arguments list
        :return None: None
        """

        if len(args) < 2:
            self.print_usage("unset <name>")
            return

        self.set_env(args[1], None)

    def do_env(self, _) -> None:
        """ List environment variables.

        :return None: None
        """

        env_data = []

        for name in self.env:
            env_data.append((name, self.env[name]))

        if not env_data:
            self.print_warning("No environment available.")
            return

        self.print_table("Environment Variables", ('Name', 'Value'),
                         *env_data)

    def do_prompt(self, args: list) -> None:
        """ Set current prompt line.

        :param list args: arguments list
        :return None: None
        """

        if len(args) < 2:
            self.print_usage("prompt <line>")
            return

        self.set_prompt(args[1])

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

    def default(self, args: list) -> None:
        """ Default unrecognized command handler.

        :param list args: line sent
        :return None: None
        """

        self.check_session()
        search = self.get_env('PATH').split(':')

        if len(args) >= 2:
            status = self.session.spawn(
                args[0], args[1:], search=search)
        else:
            status = self.session.spawn(
                args[0], [], search=search)

        if not status:
            self.print_error(f"Unrecognized command: {args[0]}!")

    def precmd(self, line: str) -> str:
        """ Do something before processing commands.

        :param str line: commands
        :return str: commands
        """

        for key, item in self.env.items():
            line = line.replace(f'${key}', str(item))

        return line

    def postcmd(self, _) -> None:
        """ Do something after each command.

        :return str: continue
        """

        self.set_prompt(self.scheme)

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

    def load_plugins(self, path: str) -> None:
        """ Load custom Pwny plugins.

        :param str path: plugins path
        :return None: None
        """

        self.check_session()

        exists, is_dir = self.exists(path)

        if exists and is_dir:
            self.plugins.import_plugins(path, self.session)

    def setup_env(self) -> None:
        """ Set up environment.

        :return None: None
        """

        self.check_session()

        self.set_env('PATH', ':'.join(
            self.search.get(self.session.info['Platform'], [])
        ))

    def start_pwny(self) -> None:
        """ Start Pwny.

        :return None: None
        """

        self.load_external(self.session.pwny_commands + str(
            self.session.info['Platform']).lower(), session=self.session)
        self.load_external(
            self.session.pwny_commands + 'generic', session=self.session)

        self.load_plugins(self.session.pwny_plugins + str(
            self.session.info['Platform']).lower())
        self.load_plugins(
            self.session.pwny_plugins + 'generic')

        self.setup_env()

    def pwny_exec(self, command: str) -> str:
        """ Execute single Pwny command.

        :param str command: command to execute (with arguments)
        :return str: command output
        """

        self.check_session()

        with io.StringIO() as buffer, redirect_stdout(buffer):
            self.set_less(False)
            self.onecmd(command)
            self.set_less(True)

            return buffer.getvalue()

    def pwny_console(self) -> None:
        """ Start Pwny console.

        :return None: None
        """

        self.set_prompt(self.prompt)
        self.set_motd(self.motd)

        if self.motd:
            self.print_empty(self.motd)

        Tips(self.session).print_random_tip()
        self.loop()
