# Console Features

The Pwny console is a full-featured interactive shell with tab completion, prompt customization, environment variables, banners, and tips.

---

## Overview

When a session starts, the console displays a **message of the day (MOTD)** showing system information alongside the OS logo, followed by an optional ASCII art banner and usage tip.

```
        .:'
    __ :'__             Name: macOS Sonoma
 .'`  `-'  ``.       Kernel: 23.4.0
:          .-'          Time: Mon Mar 17 14:22:15 2026
:         :           Vendor: Apple
 :         `-;          Arch: aarch64
  `.__.-.__.'        Memory: 8.1 GB/16.0 GB
                       UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
                   Commands: 37
                    Plugins: 3

  ____
 |  _ \__      ___ __  _   _
 | |_) \ \ /\ / / '_ \| | | |
 |  __/ \ V  V /| | | | |_| |
 |_|     \_/\_/ |_| |_|\__, |
                        |___/
         ~~ hack the planet ~~

[*] Tip: Use 'download <remote> <local>' and 'upload <local> <remote>' to
    transfer files between your machine and the target.

pwny:/Users/target$
```

---

## Prompt

The default prompt format is:

```
pwny:%line$dir%end %blue$user%end$prompt
```

This renders as:

```
pwny:/current/directory username$
```

### Prompt Variables

| Variable | Description |
|----------|-------------|
| `$dir` | Current working directory on the target |
| `$user` | Current username |
| `$prompt` | `#` for root/admin, `$` for normal user |

### ColorScript Tags in Prompt

The prompt supports ColorScript formatting:

| Tag | Effect |
|-----|--------|
| `%bold` | Bold text |
| `%line` | Underlined text |
| `%red`, `%green`, `%blue`, `%cyan`, `%yellow`, `%white` | Colored text |
| `%end` | Reset formatting |

### Customizing the Prompt

```python
# Programmatic
session.console.set_prompt('pwny:%bold$user%end@%red$dir%end> ')
```

---

## Environment Variables

The console supports local environment variables that affect behavior:

```
pwny:/$ set VERBOSE true
pwny:/$ unset VERBOSE
```

| Variable | Effect |
|----------|--------|
| `VERBOSE` | Enable verbose TLV channel output for debugging |

Environment variables are local to the console session and don't affect the target system.

---

## Banners

Pwny includes 21 ASCII art banners stored in `pwny/data/banners/`. Each banner uses ColorScript for terminal colors.

### Displaying Banners

Run the `banner` command to show a random banner:

```
pwny:/$ banner
```

### Enabling Banners at Startup

Banners can be displayed automatically at session start:

```python
session.console.set_banner(True)
```

### Banner Files

Banners are `.colors` files using the ColorScript format:

```
%comment This is a comment
%bold%cyan
  ____
 |  _ \__      ___ __  _   _
 | |_) \ \ /\ / / '_ \| | | |
 |  __/ \ V  V /| | | | |_| |
 |_|     \_/\_/ |_| |_|\__, |
                        |___/
%end
%bold   ~~ hack the planet ~~%end
```

#### ColorScript Syntax

| Tag | Description |
|-----|-------------|
| `%comment` | Comment line (not displayed) |
| `%bold` | Bold text |
| `%line` | Underlined |
| `%red`, `%green`, `%blue`, `%cyan`, `%yellow`, `%white` | Colors |
| `%end` | Reset all formatting |
| `%newline` | Explicit newline |

---

## Tips

Pwny includes 21 tips stored in `pwny/data/tips/`. Tips provide helpful hints about available features.

### Displaying Tips

```
pwny:/$ tip
[*] Tip: Use 'portfwd' to forward traffic from your local machine through the
    compromised target to reach internal hosts.
```

### Enabling Tips at Startup

```python
session.console.set_tip(True)
```

---

## Tab Completion

The console supports tab completion for:

- Command names
- File paths (on the target filesystem)
- Plugin names (for `load`)
- Option flags

Press `Tab` to auto-complete or double-press `Tab` to see all possibilities.

---

## Command History

The console maintains a command history accessible with the up/down arrow keys. This uses Python's `readline` module.

---

## Built-in Help

### General Help

```
pwny:/$ help
```

Displays all commands organized by category (Filesystem, Gather, Pivot, Manage, Evasion, etc.).

### Command-Specific Help

```
pwny:/$ help portfwd
```

Shows detailed usage, options, and description for a specific command.

---

## Programmatic Execution

Execute commands programmatically and capture output:

```python
# Execute a single command and get string output
output = session.console.pwny_exec('whoami')
print(output)

# Execute multiple commands
for cmd in ['pwd', 'whoami', 'pid']:
    result = session.console.pwny_exec(cmd)
    print(f'{cmd}: {result.strip()}')
```

---

## Plugin Commands

When plugins are loaded, their commands are added to the console:

```
pwny:/$ load evasion
[+] Plugin evasion loaded.

pwny:/$ help

...
Evasion
=======

 Command     Description
 -------     -----------
 evasion     Patch AMSI/ETW to evade AV and EDR
...
```

Unloading or closing the session removes plugin commands.

---

## Session Lifecycle

| Phase | What Happens |
|-------|-------------|
| **open** | TLV channel established, platform/arch identified |
| **interact** | Console starts, MOTD displayed, commands loaded |
| **pwny_exec** | Individual command execution (programmatic) |
| **exit** | Session closed, cleanup |

The console loop continues until `exit` is typed or the connection is lost.
