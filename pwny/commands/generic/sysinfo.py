"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from itertools import zip_longest

from pex.platform import (
    OS_LINUX,
    OS_MACOS,
    OS_IPHONE
)

from pex.string import String

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

OS_LOGO = {
    OS_LINUX: r"""     cOKxc
    .0K0kWc
    .x,':Nd
   .l... ,Wk.
  .0.     ,NN,
 .K;       0N0
..'cl.    'xO:
,''';c'':Oc',,.
  ..'.  ..,,.
""",
    OS_MACOS: r"""        .:'
    __ :'__
 .'`  `-'  ``.
:          .-'
:         :
 :         `-;
  `.__.-.__.'
""",
    OS_IPHONE: r"""⠀⠀⠀⠀⠀⢀⣤⠖⠒⠒⠒⢒⡒⠒⠒⠒⠒⠒⠲⠦⠤⢤⣤⣄⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⠟⠀⢀⠠⣐⢭⡐⠂⠬⠭⡁⠐⠒⠀⠀⣀⣒⣒⠐⠈⠙⢦⠀⠀⠀
⠀⠀⠀⣰⠏⠀⠐⠡⠪⠂⣁⣀⣀⣀⡀⠰⠀⠀⠀⢨⠂⠀⠀⠈⢢⠀⠀⢹⠀⠀
⠀⣠⣾⠿⠤⣤⡀⠤⡢⡾⠿⠿⠿⣬⣉⣷⠀⠀⢀⣨⣶⣾⡿⠿⠆⠤⠤⠌⡳⣄
⣰⢫⢁⡾⠋⢹⡙⠓⠦⠤⠴⠛⠀⠀⠈⠁⠀⠀⠀⢹⡀⠀⢠⣄⣤⢶⠲⠍⡎⣾
⢿⠸⠸⡇⠶⢿⡙⠳⢦⣄⣀⠐⠒⠚⣞⢛⣀⡀⠀⠀⢹⣶⢄⡀⠀⣸⡄⠠⣃⣿
⠈⢷⣕⠋⠀⠘⢿⡶⣤⣧⡉⠙⠓⣶⠿⣬⣀⣀⣐⡶⠋⣀⣀⣬⢾⢻⣿⠀⣼⠃
⠀⠀⠙⣦⠀⠀⠈⠳⣄⡟⠛⠿⣶⣯⣤⣀⣀⣏⣉⣙⣏⣉⣸⣧⣼⣾⣿⠀⡇⠀
⠀⠀⠀⠘⢧⡀⠀⠀⠈⠳⣄⡀⣸⠃⠉⠙⢻⠻⠿⢿⡿⢿⡿⢿⢿⣿⡟⠀⣧⠀
⠀⠀⠀⠀⠀⠙⢦⣐⠤⣒⠄⣉⠓⠶⠤⣤⣼⣀⣀⣼⣀⣼⣥⠿⠾⠛⠁⠀⢿⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠦⣭⣐⠉⠴⢂⡤⠀⠐⠀⠒⠒⢀⡀⠀⠄⠁⡠⠀⢸⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠲⢤⣀⣀⠉⠁⠀⠀⠀⠒⠒⠒⠉⠀⢀⡾⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠲⠦⠤⠤⠤⠤⠴⠞⠋⠀⠀
"""
}

OS_COLOR = {
    OS_LINUX: '%yellow',
    OS_MACOS: '%dark',
    OS_IPHONE: '%blue',
}


class ExternalCommand(Command, String):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "sysinfo",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Get session system properties.",
            'Usage': "sysinfo",
            'MinArgs': 0
        })

    def run(self, _):
        system = self.session.send_command(tag=BUILTIN_SYSINFO)

        if system.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to fetch system information!")
            return

        local_time = self.session.send_command(tag=BUILTIN_TIME)

        data = {
            'Name': system.get_string(BUILTIN_TYPE_PLATFORM),
            'Kernel': system.get_string(BUILTIN_TYPE_VERSION),
            'Time': local_time.get_string(TLV_TYPE_STRING),
            'Vendor': system.get_string(BUILTIN_TYPE_VENDOR),
            'Arch': system.get_string(BUILTIN_TYPE_ARCH),
            'Memory': (
                f'{self.size_normalize(system.get_long(BUILTIN_TYPE_RAM_USED))}/'
                f'{self.size_normalize(system.get_long(BUILTIN_TYPE_RAM_TOTAL))}'
            ),
            'UUID': self.session.uuid,
        }

        platform = self.session.info['Platform']
        logo = OS_LOGO[platform].splitlines()
        color = OS_COLOR[platform]

        text_max_len = len(max(data)) + 2
        logo_max_len = max(len(line) for line in logo) + 1
        self.print_empty()

        for logo_line, (key, val) in zip_longest(logo[:len(data)], data.items(), fillvalue=''):
            self.print_empty(f'{color} {logo_line.ljust(logo_max_len, " ")} %end',
                             start='', end='')
            self.print_empty(f'{color} {key.rjust(text_max_len, " ")}: %end',
                             start='', end='')
            self.print_empty(val, start='')

        for line in logo[len(data):]:
            self.print_empty(f'{color} {line} %end', start='')

        self.print_empty()
