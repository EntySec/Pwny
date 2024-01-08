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

from typing import Union, Optional

from pex.arch.types import Arch
from pex.platform.types import Platform

from hatsploit.lib.payload import Payload


class Pwny(object):
    """ Main class of pwny module.

    This main class of pwny module is intended for providing
    an implementation of Pwny manipulation methods.
    """

    def __init__(self):
        super().__init__()

        self.pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'

        self.pwny_data = self.pwny + 'data/'
        self.pwny_libs = self.pwny + 'libs/'

        self.pwny_plugins = self.pwny + 'plugins/'
        self.pwny_commands = self.pwny + 'commands/'

        self.templates = self.pwny + 'templates/'

    def get_template(self, platform: Union[Platform, str],
                     arch: Union[Arch, str], extension: str = '') -> bytes:
        """ Get Pwny template.

        :param Union[Platform, str] platform: platform to get Pwny template for
        :param Union[Arch, str] arch: architecture to get Pwny template for
        :param str extension: extension of the file
        :return bytes: Pwny template
        """

        payload = self.templates + '/'.join((str(platform), str(arch) + '.' + extension))

        if os.path.exists(payload):
            return open(payload, 'rb').read()
        return b''

    def get_implant(self, platform: Optional[Union[Platform, str]] = None,
                    arch: Optional[Union[Arch, str]] = None,
                    payload: Optional[Payload] = None) -> bytes:
        """ Get Pwny implant.

        :param Optional[Union[Platform, str]] platform: platform to get Pwny implant for
        :param Optional[Union[Arch, str]] arch: architecture to get Pwny implant for
        :param Optional[Payload] payload: if payload object is not None, ignore
            platform and arch
        :return bytes: Pwny implant
        """

        if payload is not None:
            platform = payload.details['Platform']
            arch = payload.details['Arch']

        return self.get_template(platform, arch, 'bin')
