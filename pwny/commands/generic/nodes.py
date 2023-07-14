"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from hatsploit.lib.command import Command

from pwny.nodes import Nodes


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.nodes = Nodes()

        self.details = {
            'Category': "local",
            'Name': "nodes",
            'Authors': [
                'Ivan Nikolsky (enty8080) - command developer'
            ],
            'Description': "Manage nodes.",
            'Usage': "nodes <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                '-l': ['', "List all nodes."],
                '-d': ['<id>', "Delete specific node."],
                '-a': ['<src_pair> <dst_pair>', "Add node."],
            }
        }

    def run(self, argc, argv):
        choice = argv[1]

        if choice == '-l':
            self.nodes.show_nodes()

        elif choice == '-d':
            self.nodes.delete_node(int(argv[2]), self.session)

        elif choice == '-a':
            src_pair = argv[2].split(':')
            dst_pair = argv[3].split(':')

            self.nodes.add_node(src_host=src_pair[0], src_port=int(src_pair[1]),
                                dst_host=dst_pair[0], dst_port=int(dst_pair[1]),
                                session=self.session)
