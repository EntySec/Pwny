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

from .plugins import Plugins

from hatsploit.core.cli.badges import Badges

from hatsploit.lib.session import Session
from hatsploit.lib.commands import Commands


class Console(Plugins, Badges, Commands):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing
    Pwny main console.
    """

    prompt = '%linepwnypreter%end > '

    commands = [
        ('exit', 'Terminate Pwny session.'),
        ('help', 'Show available commands.'),
        ('load', 'Load Pwny plugin.'),
        ('plugins', 'List Pwny plugins.'),
        ('quit', 'Stop interaction.'),
        ('unload', 'Unload Pwny plugin.')
    ]

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

        commands = self.load_commands(
            session.pwny + 'commands/' + session.details['Platform'].lower()
        )

        commands.update(
            self.load_commands(
                session.pwny + 'commands/generic'
            )
        )

        for command in commands:
            commands[command].session = session

        self.import_plugins(
            session.pwny + 'plugins/' + session.details['Platform'].lower(), session
        )

    def pwny_console(self, session: Session) -> None:
        """ Start Pwny console.

        :param Session session: session to start Pwny console for
        :return None: None
        """

        self.start_pwny(session)

        if self.check_session(session):
            while True:
                if self.catch(self.pwny_shell, [session]):
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

            elif command[0] == 'help':
                self.print_table("Core Commands", ('Command', 'Description'), *[
                    ('exit', 'Terminate Pwny session.'),
                    ('help', 'Show available commands.'),
                    ('load', 'Load Pwny plugin.'),
                    ('plugins', 'List Pwny plugins.'),
                    ('quit', 'Stop interaction.'),
                    ('unload', 'Unload Pwny plugin.')
                ])

                self.show_commands(commands)

            elif command[0] == 'exit':
                session.send_command("exit")
                session.channel.terminated = True

            else:
                self.check(session)

                if not self.execute_custom_command(command, commands, False):
                    self.execute_custom_plugin_command(command, self.loaded_plugins)

        return False
