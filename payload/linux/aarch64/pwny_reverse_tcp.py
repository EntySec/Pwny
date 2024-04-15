"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny import Pwny
from pwny.session import PwnySession

from pex.assembler import Assembler

from hatsploit.lib.payload.basic import *


class HatSploitPayload(Payload, Handler, Pwny, Assembler):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "Linux aarch64 Pwny Reverse TCP",
            'Payload': "linux/aarch64/pwny_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer'
            ],
            'Description': "Linux aarch64 (arm64) Pwny Reverse TCP",
            'Arch': ARCH_AARCH64,
            'Platform': OS_LINUX,
            'Session': PwnySession,
            'Rank': "high",
            'Type': "reverse_tcp"
        }



    def implant(self):
        pass

    def run(self):
        pass
