#!/usr/bin/env python3

#
# This command requires HatSploit: https://hatsploit.netlify.app
# Current source: https://github.com/EntySec/HatSploit
#

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    details = {
        'Category': "transfer",
        'Name': "download",
        'Authors': [
            'Ivan Nikolsky (enty8080) - command developer'
        ],
        'Description': "Download remote file.",
        'Usage': "download <remote_file> <local_path>",
        'MinArgs': 2
    }

    def run(self, argc, argv):
        self.session.download(argv[1], argv[2])
