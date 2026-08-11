"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "evasion",
            'Name': "secure",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Secure communication.",
            'Options': [
                (
                    ('-a', '--algorithm'),
                    {
                        'help': "Select appropriate algorithm.",
                        'choices': ['aes256_cbc', 'chacha20'],
                        'required': False
                    }
                )
            ]
        })

    def run(self, args):
        if args.algorithm == 'chacha20':
            algorithm = ALGO_CHACHA20
        else:
            algorithm = ALGO_AES256_CBC

        self.session.secure(algo=algorithm)
