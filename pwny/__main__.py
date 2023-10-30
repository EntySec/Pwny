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

import os

from typing import Union

from pex.exe import EXE
from pex.socket import Socket
from pex.string import String

from pex.arch.types import Arch
from pex.platform.types import Platform


class Pwny(EXE, Socket, String):
    """ Main class of pwny module.

    This main class of pwny module is intended for providing
    an implementation of Pwny manipulation methods.
    """

    def __init__(self):
        super().__init__()

        self.templates = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/templates/'

    def get_template(self, platform: Union[Platform, str],
                     arch: Union[Arch, str], extension: str = '') -> bytes:
        """ Get Pwny template.

        :param Union[Platform, str] platform: platform to get Pwny template for
        :param Union[Arch, str] arch: architecture to get Pwny template for
        :param str extension: extension of the file
        :return bytes: Pwny template
        """

        payload = self.templates + '/'.join((str(platform), str(arch) + extension))

        if os.path.exists(payload):
            return open(payload, 'rb').read()
        return b''

    def get_loader(self, platform: Union[Platform, str],
                   arch: Union[Arch, str]) -> bytes:
        """ Get Pwny loader for migrations.

        :param Union[Platform, str] platform: platform to get Pwny loader for
        :param Union[Arch, str] arch: architecture to get Pwny loader for
        :return bytes: Pwny loader
        """

        return self.get_template(platform, arch, '.ldr')

    def get_implant(self, platform: Union[Platform, str],
                    arch: Union[Arch, str]) -> bytes:
        """ Get Pwny implant.

        :param Union[Platform, str] platform: platform to get Pwny implant for
        :param Union[Arch, str] arch: architecture to get Pwny implant for
        :return bytes: Pwny implant
        """

        return self.get_template(platform, arch, '.bin')
