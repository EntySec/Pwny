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
import glob

from typing import Union


class Pwny(object):
    """ Main class of pwny module.

    This main class of pwny module is intended to provide an
    interface to craft Pwny implant.
    """

    def __init__(self, target: str, options: dict = {}) -> None:
        """ Initialize Pwny and select target.

        :param str target: target to build for (e.g. aarch64-apple-darwin)
        or target triplet in glob format (e.g. i?86-*-*)
        :param dict options: options (e.g. key -u, value tcp://127.0.0.1:8888)
        :return None: None
        """

        self.root = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'
        self.templates = self.root + 'templates/'

        self.target = self.templates + target
        self.options = options

    @staticmethod
    def shorten_option(option: str) -> Union[str, None]:
        """ Produce shortened representation of an option.

        :param str option: option to format
        :return Union[str, None]: shortened option
        """

        if option.lower() == 'uri':
            return '-u'
        elif option.lower() == 'uuid':
            return '-U'

    def add_options(self, binary: bytes) -> bytes:
        """ Add options to binary.

        :param bytes binary: binary data
        :return bytes: updated binary data
        """

        if not self.options:
            return binary

        sign = b"INJECT_OPTIONS"
        length = 2000
        options = "pwny"

        for key, value in self.options.items():
            options += f" {self.shorten_option(key)} {str(value)}"

        if len(options) > length:
            raise RuntimeError(
                f"Options list too big ({str(len(options))} > {str(length)})!")

        options = options.encode()
        options += b'\x00' * (length - len(options))

        return binary.replace(sign + b' ' * (length - len(sign)), options)

    def to_binary(self, format: str = 'exe') -> Union[bytes, None]:
        """ Convert implant to binary image.

        :param str format: format (e.g. exe, bin, so, dylib)
        :return Union[bytes, None]: binary image if exists else None
        """

        binary = self.target + '.' + format
        result = glob.glob(binary)

        if not result:
            return

        with open(result[0], 'rb') as f:
            return self.add_options(f.read())
