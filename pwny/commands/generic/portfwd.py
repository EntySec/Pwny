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
from hatsploit.lib.ui.jobs import Job

NET_STATUS_CLOSED = 0
NET_STATUS_OPEN = 3


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "pivot",
            'Name': "portfwd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Manage port forwarding.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List existing forwarding rules.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-d', '--delete'),
                    {
                        'help': "Delete existing forwarding rule by ID.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-L',),
                    {
                        'help': "Local host to listen on (optional).",
                        'metavar': 'HOST',
                        'dest': 'lhost'
                    }
                ),
                (
                    ('-P',),
                    {
                        'help': "Local port to listen on (optional).",
                        'metavar': 'PORT',
                        'type': int,
                        'dest': 'lport'
                    }
                ),
                (
                    ('-p',),
                    {
                        'help': "Remote port to connect to.",
                        'metavar': 'PORT',
                        'type': int,
                        'dest': 'rport'
                    }
                ),
                (
                    ('-r',),
                    {
                        'help': "Remote host to connect to.",
                        'metavar': 'HOST',
                        'dest': 'rhost'
                    }
                )
            ]
        })

        self.rules = {}

    @staticmethod
    def read_event(packet, listener):
        listener.send(packet.get_raw(PIPE_TYPE_BUFFER))

    @staticmethod
    def heartbeat_event(packet, status) -> None:
        status['Status'] = packet.get_int(PIPE_TYPE_HEARTBEAT)

    def rule_thread(self, host, port, uri, job):
        listener = TCPListener(
            host=host,
            port=port,
            timeout=None
        )

        def shutdown_submethod(server):
            try:
                server.stop()
            except RuntimeError:
                return

        job.set_exit(target=shutdown_submethod, args=(listener,))
        listener.listen()

        while True:
            status = {'Status': NET_STATUS_CLOSED}
            listener.accept()

            pipe_id = self.session.pipes.create_pipe(
                pipe_type=NET_PIPE_CLIENT,
                args={
                    NET_TYPE_URI: uri
                },
                flags=PIPE_INTERACTIVE
            )

            self.session.pipes.create_event(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id,
                pipe_data=PIPE_TYPE_HEARTBEAT,
                target=self.heartbeat_event,
                args=(status,)
            )

            while status['Status'] != NET_STATUS_OPEN:
                pass

            self.session.pipes.create_event(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id,
                pipe_data=PIPE_TYPE_BUFFER,
                target=self.read_event,
                args=(listener,)
            )

            while True:
                try:
                    buffer = listener.recv(TLV_FILE_CHUNK)
                except Exception:
                    break

                if not buffer:
                    break

                self.session.pipes.write_pipe(
                    pipe_type=NET_PIPE_CLIENT,
                    pipe_id=pipe_id,
                    buffer=buffer
                )

            listener.disconnect()

            self.session.pipes.destroy_pipe(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id
            )

    def run(self, args):
        if args.list:
            rules = []

            for rule_id, rule in self.rules.items():
                rules.append((rule_id, rule['Rule']))

            if not rules:
                self.print_warning("No forwarding rules set yet.")
                return

            self.print_table('Forwarding rules', ('ID', 'Rule'), *rules)

        elif args.delete is not None:
            if args.delete not in self.rules:
                self.print_error(f"No such rule: {str(args.delete)}!")
                return

            self.print_process(f"Flushing rule {str(args.delete)}...")

            job = self.rules[args.delete]['Job']
            job.shutdown()
            job.join()

            self.rules.pop(args.delete)
            self.print_success(f"Rule {str(args.delete)} deleted!")

        elif args.rhost and args.rport:
            uri = f'tcp://{args.rhost}:{str(args.rport)}'
            self.print_process(f"Adding rule {uri}...")

            rule_id = 0
            while rule_id in self.rules or \
                    rule_id < len(self.rules):
                rule_id += 1

            job = Job(
                target=self.rule_thread,
                args=(args.lhost or '0.0.0.0',
                      args.lport or args.rport,
                      uri))
            job.pass_job = True

            rule = (
                f"{args.lhost or '0.0.0.0'}:{str(args.lport) or str(args.rport)}"
                f" -> {args.rhost}:{str(args.rport)}"
            )

            self.rules.update({
                rule_id: {
                    'Rule': rule,
                    'Job': job,
                    'URI': uri
                }
            })
            job.start()

            self.print_success(f"Rule activated as {str(rule_id)}!")
