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

from .__main__ import Pwny

from hatsploit.lib.session import Session


class Migrate(Pwny):
    """ Subclass of pwny module.

    This subclass of pwny module is intended for providing a
    tools for migration.
    """

    def __init__(self, session: Session) -> None:
        """ Initialize migration for session.

        :param Session session: session to migrate
        :return None: None
        """

        super().__init__()

        self.session = session

    def migrate(self, pid: int) -> bool:
        """ Migrate to the specific PID.

        :param int pid: process ID
        :return bool: True if success else False
        """

        platform = self.session.details['Platform']
        arch = self.session.details['Arch']

        loader = self.get_loader(
            platform=platform,
            arch=arch)

        if loader:
            self.session.send_command('migrate', args=[
                pid.to_bytes(4, 'little'), loader])

            session.open(session.channel.sock.sock)
        else:
            raise RuntimeError(f"Loader was not found for {platform}/{arch}!")