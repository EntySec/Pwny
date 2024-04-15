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
import pathlib

from typing import Union, Optional

from pex.arch.types import Arch
from pex.platform.types import Platform

from hatsploit.lib.payload import Payload
from hatsploit.lib.loot import Loot


class Pwny(object):
    """ Main class of pwny module.

    This main class of pwny module is intended for providing
    an implementation of Pwny manipulation methods.
    """

    def __init__(self):
        super().__init__()

        self.pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'

        self.pwny_data = self.pwny + 'data/'
        self.pwny_tabs = self.pwny + 'tabs/'
        self.pwny_loot = f'{pathlib.Path.home()}/.pwny/'

        self.pwny_plugins = self.pwny + 'plugins/'
        self.pwny_commands = self.pwny + 'commands/'

        self.templates = self.pwny + 'templates/'

    def get_template(self, target: str, extension: str = '') -> bytes:
        """ Get Pwny template.

        :param str target: target (e.g. x86_64-linux-musl, list - README.md)
        :param str extension: extension of the file (e.g. bin, exe, so)
        :return bytes: Pwny template
        """

        template = self.templates + target

        if extension:
            target += '.' + extension

        if os.path.exists(template):
            return open(template, 'rb').read()
        return b''
