"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import ctypes
import threading

from pwny.api import *
from pwny.types import *

from pex.proto.tcp import TCPListener

from badges.cmd import Command


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "pivot",
            'Name': "portfwd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage port forwarding.",
            'Usage': "portfwd <option> [arguments]",
            'MinArgs': 1,
            'Options': {
                'list': ['', 'List existing forwarding rules.'],
                'add': ['<rule>', 'Add forwarding rule. (use local -> remote for syntax)'],
                'delete': ['<id>', 'Delete existing forwarding rule.'],
            }
        })

        self.rules = {}

    @staticmethod
    def read_event(packet, listener):
        listener.send(packet.get_raw(PIPE_TYPE_BUFFER))

    @staticmethod
    def heartbeat_event(packet, rule) -> None:
        if packet.get_int(PIPE_TYPE_HEARTBEAT) == 3:
            rule['Running'] = True
            return

        rule['Running'] = False

    def rule_thread(self, rule_id):
        rule = self.rules[rule_id]

        while True:
            rule['Listener'] = TCPListener(
                host=rule['Host'],
                port=rule['Port'],
                timeout=None
            )
            rule['Listener'].listen()
            rule['Listener'].accept()

            pipe_id = self.session.pipes.create_pipe(
                pipe_type=NET_PIPE_CLIENT,
                args={
                    NET_TYPE_URI: rule['URI']
                },
                flags=PIPE_INTERACTIVE
            )

            self.session.pipes.create_event(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id,
                pipe_data=PIPE_TYPE_HEARTBEAT,
                target=self.heartbeat_event,
                args=(rule,)
            )

            while not rule['Running']:
                pass

            self.session.pipes.create_event(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id,
                pipe_data=PIPE_TYPE_BUFFER,
                target=self.read_event,
                args=(rule['Listener'],)
            )

            while not rule['Flush']:
                try:
                    buffer = rule['Listener'].recv(TLV_FILE_CHUNK)
                except Exception:
                    break

                if not buffer:
                    break

                self.session.pipes.write_pipe(
                    pipe_type=NET_PIPE_CLIENT,
                    pipe_id=pipe_id,
                    buffer=buffer
                )

            rule['Listener'].disconnect()
            rule['Listener'].stop()

            self.session.pipes.destroy_pipe(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id
            )

    def run(self, args):
        if args[1] == 'list':
            rules = []

            for rule_id, rule in self.rules.items():
                rules.append((rule_id, rule['Rule']))

            if not rules:
                self.print_warning("No forwarding rules set yet.")
                return

            self.print_table('Forwarding rules', ('ID', 'Rule'), *rules)

        elif args[1] == 'delete':
            rule_id = int(args[2])

            if rule_id not in self.rules:
                self.print_error(f"No such rule: {args[2]}!")
                return

            self.print_process(f"Flushing rule {args[2]}...")

            self.rules[rule_id]['Flush'] = True
            thread = self.rules[rule_id]['Thread']

            if thread.is_alive():
                exc = ctypes.py_object(SystemExit)
                res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread.ident), exc)

                if res > 1:
                    ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)

            self.rules.pop(rule_id)
            self.print_success(f"Rule {args[2]} deleted!")

        elif args[1] == 'add':
            self.print_process(f"Adding rule {args[2]}...")

            rule = args[2].split('->')
            host, port = rule[0].split(':')

            rule_id = len(self.rules)

            thread = threading.Thread(
                target=self.rule_thread,
                args=(rule_id,)
            )
            thread.setDaemon(True)

            self.rules[rule_id] = {
                'Rule': args[2],
                'Host': host,
                'Port': int(port),
                'URI': f'tcp://{rule[1]}',
                'Flush': False,
                'Thread': thread,
                'Running': False,
            }
            thread.start()

            self.print_success(f"Rule {args[2]} activated!")
