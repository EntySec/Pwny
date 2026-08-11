"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import socket
import struct
import threading

from pwny.api import *
from pwny.types import *

from pex.proto.tcp import TCPListener

from badges.cmd import Command
from hatsploit.lib.ui.jobs import Job

NET_STATUS_CLOSED = 0
NET_STATUS_OPEN = 3

SOCKS_VERSION = 5


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "pivot",
            'Name': "socks",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Manage SOCKS5 proxy through the implant.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-s', '--start'),
                    {
                        'help': "Start SOCKS5 proxy.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-S', '--stop'),
                    {
                        'help': "Stop SOCKS5 proxy.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-l', '--lhost'),
                    {
                        'help': "Local address to bind (default: 127.0.0.1).",
                        'metavar': 'HOST',
                        'default': '127.0.0.1',
                    }
                ),
                (
                    ('-p', '--port'),
                    {
                        'help': "Local port for SOCKS5 listener (default: 1080).",
                        'metavar': 'PORT',
                        'type': int,
                        'default': 1080,
                    }
                ),
            ]
        })

        self.proxy_job = None

    @staticmethod
    def _read_event(packet, client_sock):
        """Forward implant->target data back to the SOCKS client."""
        data = packet.get_raw(PIPE_TYPE_BUFFER)
        if data:
            try:
                client_sock.sendall(data)
            except Exception:
                pass

    @staticmethod
    def _heartbeat_event(packet, status):
        status['Status'] = packet.get_int(PIPE_TYPE_HEARTBEAT)

    def _socks5_handshake(self, client):
        """Perform SOCKS5 greeting and return (host, port) or None on failure."""

        # Greeting
        data = client.recv(2)
        if len(data) < 2 or data[0] != SOCKS_VERSION:
            return None

        nmethods = data[1]
        methods = client.recv(nmethods)
        if len(methods) < nmethods:
            return None

        # No auth (0x00): reply with version + chosen method
        client.sendall(struct.pack('BB', SOCKS_VERSION, 0x00))

        # Connection request
        data = client.recv(4)
        if len(data) < 4 or data[0] != SOCKS_VERSION or data[1] != 0x01:
            # Only CONNECT (0x01) is supported
            if len(data) >= 4:
                reply = struct.pack('BBBBIH', SOCKS_VERSION, 0x07, 0x00,
                                    0x01, 0, 0)
                client.sendall(reply)
            return None

        atyp = data[3]

        if atyp == 0x01:
            # IPv4
            raw = client.recv(4)
            if len(raw) < 4:
                return None
            dst_addr = socket.inet_ntoa(raw)

        elif atyp == 0x03:
            # Domain name
            length = client.recv(1)
            if len(length) < 1:
                return None
            domain = client.recv(length[0])
            if len(domain) < length[0]:
                return None
            dst_addr = domain.decode('utf-8', errors='replace')

        elif atyp == 0x04:
            # IPv6
            raw = client.recv(16)
            if len(raw) < 16:
                return None
            dst_addr = socket.inet_ntop(socket.AF_INET6, raw)

        else:
            return None

        port_raw = client.recv(2)
        if len(port_raw) < 2:
            return None

        dst_port = struct.unpack('!H', port_raw)[0]
        return dst_addr, dst_port

    def _handle_client(self, client_sock):
        """Handle a single SOCKS5 client connection."""

        try:
            result = self._socks5_handshake(client_sock)
            if result is None:
                client_sock.close()
                return

            dst_addr, dst_port = result
            uri = f'tcp://{dst_addr}:{dst_port}'

            # Open a pipe to the target via the implant
            status = {'Status': NET_STATUS_CLOSED}

            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=NET_PIPE_CLIENT,
                    args={NET_TYPE_URI: uri},
                    flags=PIPE_INTERACTIVE,
                )
            except RuntimeError:
                # Connection failed — send SOCKS reply: host unreachable
                reply = struct.pack('BBBBIH', SOCKS_VERSION, 0x04,
                                    0x00, 0x01, 0, 0)
                client_sock.sendall(reply)
                client_sock.close()
                return

            # Wait for connection to be established
            self.session.pipes.create_event(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id,
                pipe_data=PIPE_TYPE_HEARTBEAT,
                target=self._heartbeat_event,
                args=(status,),
            )

            timeout = 30
            waited = 0.0
            import time
            while status['Status'] != NET_STATUS_OPEN and waited < timeout:
                time.sleep(0.05)
                waited += 0.05

            if status['Status'] != NET_STATUS_OPEN:
                reply = struct.pack('BBBBIH', SOCKS_VERSION, 0x04,
                                    0x00, 0x01, 0, 0)
                client_sock.sendall(reply)
                client_sock.close()
                self.session.pipes.destroy_pipe(
                    pipe_type=NET_PIPE_CLIENT,
                    pipe_id=pipe_id,
                )
                return

            # Send SOCKS success reply
            reply = struct.pack('BBBBIH', SOCKS_VERSION, 0x00,
                                0x00, 0x01, 0, 0)
            client_sock.sendall(reply)

            # Set up read event: implant -> SOCKS client
            self.session.pipes.create_event(
                pipe_type=NET_PIPE_CLIENT,
                pipe_id=pipe_id,
                pipe_data=PIPE_TYPE_BUFFER,
                target=self._read_event,
                args=(client_sock,),
            )

            # Forward loop: SOCKS client -> implant
            while True:
                try:
                    data = client_sock.recv(TLV_FILE_CHUNK)
                except Exception:
                    break

                if not data:
                    break

                self.session.pipes.write_pipe(
                    pipe_type=NET_PIPE_CLIENT,
                    pipe_id=pipe_id,
                    buffer=data,
                )

        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

            try:
                self.session.pipes.destroy_pipe(
                    pipe_type=NET_PIPE_CLIENT,
                    pipe_id=pipe_id,
                )
            except Exception:
                pass

    def _proxy_thread(self, host, port, job):
        """Main SOCKS5 listener thread."""

        listener = TCPListener(host=host, port=port, timeout=None)

        def shutdown_submethod(server):
            try:
                server.stop()
            except RuntimeError:
                pass

        job.set_exit(target=shutdown_submethod, args=(listener,))
        listener.listen()

        while True:
            try:
                listener.accept()
            except Exception:
                break

            # Each SOCKS client is handled in its own thread
            client_thread = threading.Thread(
                target=self._handle_client,
                args=(listener.client,),
                daemon=True,
            )
            client_thread.start()

    def run(self, args):
        if args.start:
            if self.proxy_job is not None:
                self.print_error("SOCKS5 proxy is already running!")
                return

            self.print_process(
                f"Starting SOCKS5 proxy on {args.lhost}:{args.port}..."
            )

            job = Job(
                target=self._proxy_thread,
                args=(args.lhost, args.port),
            )
            job.pass_job = True
            self.proxy_job = job
            job.start()

            self.print_success(
                f"SOCKS5 proxy listening on {args.lhost}:{args.port}"
            )

        elif args.stop:
            if self.proxy_job is None:
                self.print_error("No SOCKS5 proxy is running!")
                return

            self.print_process("Stopping SOCKS5 proxy...")
            self.proxy_job.shutdown()
            self.proxy_job.join()
            self.proxy_job = None
            self.print_success("SOCKS5 proxy stopped.")

        else:
            if self.proxy_job is not None:
                self.print_information(
                    f"SOCKS5 proxy is running on "
                    f"{self.proxy_job._args[0]}:{self.proxy_job._args[1]}"
                )
            else:
                self.print_information("No SOCKS5 proxy is running.")
