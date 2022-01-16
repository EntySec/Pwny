#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import os
import json

from hatvenom import HatVenom
from hatsploit.utils.string import StringTools


class Pwny(StringTools):
    hatvenom = HatVenom()
    templates = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/templates/'

    def get_template(self, platform, arch):
        payload = self.templates + platform + '/' + arch + '.bin'

        if os.path.exists(payload):
            return open(payload, 'rb').read()
        return None

    def encode_data(self, port, host=None):
        if not host:
            data = json.dumps({
                'port': str(port)
            })
        else:
            data = json.dumps({
                'host': host,
                'port': str(port)
            })

        return self.base64_string(data)

    def get_pwny(self, platform, arch, port, host=None):
        template = self.get_template(platform, arch)
        data = self.encode_data(port, host)

        return self.hatvenom.generate(platform, arch, template, {
            'data': data
        })
