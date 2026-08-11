# Plugin Development Guide

Pwny plugins (called **TABs** — The Additional Bundles) are dynamically loaded extensions that add commands and capabilities to the implant at runtime. This guide covers writing plugins for POSIX targets (Linux, macOS, iOS).

---

## Overview

A Pwny plugin has two components:

1. **C plugin** — native code that runs inside the implant, registered as API calls
2. **Python wrapper** — console-side code that sends TLV commands and displays results

```
┌──────────────────────────────────────────┐
│  Operator Console (Python)               │
│  pwny/plugins/<platform>/myplugin.py     │
│  ├── HatSploitPlugin class               │
│  ├── Command definitions                 │
│  └── TLV send/receive logic              │
└──────────────┬───────────────────────────┘
               │ TLV over C2 channel
┌──────────────▼───────────────────────────┐
│  Implant (C)                             │
│  plugins/myplugin/myplugin.c             │
│  ├── API call handlers                   │
│  └── Native OS interaction               │
└──────────────────────────────────────────┘
```

---

## Part 1: Writing the C Plugin

### Project Structure

```
plugins/
└── myplugin/
    └── myplugin.c
```

### POSIX Plugin (Linux / macOS)

POSIX plugins are standalone executables that communicate with the implant via pipe IPC.

```c
#include <pwny/tab.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/tlv.h>
#include <pwny/tlv_types.h>

/* Define TLV tags for your API calls */
#define MYPLUGIN_HELLO \
    TLV_TAG_CUSTOM(API_CALL_DYNAMIC, TAB_BASE, API_CALL)

#define MYPLUGIN_GREET \
    TLV_TAG_CUSTOM(API_CALL_DYNAMIC, TAB_BASE, API_CALL + 1)

/* Define custom TLV types for your data */
#define TLV_TYPE_GREETING \
    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)

/* API call handler — receives a C2 request, returns a TLV response */
static tlv_pkt_t *hello(c2_t *c2)
{
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_GREETING, "Hello from myplugin!");

    return result;
}

static tlv_pkt_t *greet(c2_t *c2)
{
    char *name;
    char buffer[256];
    tlv_pkt_t *result;

    /* Read input from request */
    tlv_pkt_get_string(c2->request, TLV_TYPE_GREETING, &name);

    snprintf(buffer, sizeof(buffer), "Hello, %s!", name);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_GREETING, buffer);

    return result;
}

int main(void)
{
    tab_t *tab;

    tab = tab_create();
    tab_setup(tab);

    /* Register API call handlers */
    tab_register_call(tab, MYPLUGIN_HELLO, hello);
    tab_register_call(tab, MYPLUGIN_GREET, greet);

    /* Start the tab event loop */
    tab_start(tab);
    tab_destroy(tab);

    return 0;
}
```

**Key points:**
- Every handler returns `tlv_pkt_t *` and takes `c2_t *` as argument
- Use `api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request)` to create a response
- Use `tlv_pkt_add_*` / `tlv_pkt_get_*` for serialization
- Tags start at `API_CALL` and increment: `API_CALL + 1`, `API_CALL + 2`, etc.
- Custom types start at `API_TYPE` and increment similarly

---

## Part 2: Writing the Python Wrapper

### Plugin File Structure

```
pwny/plugins/<platform>/myplugin.py
```

Where `<platform>` is `linux`, `macos`, `iphone`, or `generic` (all platforms).

### Plugin Template

```python
"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


# Define TLV tags — must match the C side exactly
MYPLUGIN_HELLO = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
MYPLUGIN_GREET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

# Define custom TLV types — must match the C side exactly
TLV_TYPE_GREETING = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "My Plugin",
            'Plugin': "myplugin",
            'Authors': [
                'Your Name - plugin developer',
            ],
            'Description': "A sample plugin that says hello.",
        })

        # Define commands this plugin provides
        self.commands = [
            Command({
                'Category': "gather",
                'Name': "hello",
                'Description': "Say hello from the implant.",
            }),
            Command({
                'Category': "gather",
                'Name': "greet",
                'Description': "Greet someone by name.",
                'Usage': "greet <name>",
                'MinArgs': 1,
                'Options': [
                    (
                        ('name',),
                        {
                            'help': "Name to greet.",
                        }
                    ),
                ]
            }),
        ]

    def hello(self, args):
        """Handler for the 'hello' command."""
        result = self.session.send_command(
            tag=MYPLUGIN_HELLO,
            plugin=self.plugin  # Routes to the loaded TAB
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed!")
            return

        greeting = result.get_string(TLV_TYPE_GREETING)
        self.print_information(greeting)

    def greet(self, args):
        """Handler for the 'greet' command."""
        result = self.session.send_command(
            tag=MYPLUGIN_GREET,
            plugin=self.plugin,
            args={
                TLV_TYPE_GREETING: args.name
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed!")
            return

        self.print_information(result.get_string(TLV_TYPE_GREETING))
```

### Key Concepts

| Concept | Details |
|---------|---------|
| `Plugin` field | Must match the directory name under `plugins/` and the tab filename |
| `self.commands` | List of `Command` objects — each becomes a console command |
| `self.plugin` | Set automatically after loading; routes TLV to correct TAB |
| `self.session` | The active `PwnySession` with `send_command()` |
| Method naming | The method name must match the command's `Name` field |
| `plugin=self.plugin` | **Required** in `send_command()` — tells the implant which TAB to dispatch to |

### Command Options

Commands use Python's argparse-style options:

```python
Command({
    'Name': "mycommand",
    'Description': "Do something.",
    'MinArgs': 1,
    'Options': [
        # Positional argument
        (
            ('target',),
            {
                'help': "Target to operate on.",
            }
        ),
        # Flag with value
        (
            ('-o', '--output'),
            {
                'help': "Output file.",
                'metavar': 'PATH',
            }
        ),
        # Boolean flag
        (
            ('-v', '--verbose'),
            {
                'help': "Verbose output.",
                'action': 'store_true',
            }
        ),
        # Choice
        (
            ('-t', '--type'),
            {
                'help': "Type of operation.",
                'choices': ['fast', 'thorough'],
                'default': 'fast',
            }
        ),
    ]
})
```

Arguments are passed as an argparse `Namespace` object:

```python
def mycommand(self, args):
    print(args.target)      # positional
    print(args.output)      # --output value
    print(args.verbose)     # True/False
    print(args.type)        # 'fast' or 'thorough'
```

### Print Methods

Plugins inherit badge methods for formatted output:

| Method | Output |
|--------|--------|
| `self.print_information(msg)` | `[i] msg` |
| `self.print_success(msg)` | `[+] msg` |
| `self.print_error(msg)` | `[-] msg` |
| `self.print_warning(msg)` | `[!] msg` |
| `self.print_process(msg)` | `[*] msg` |
| `self.print_empty(msg)` | `msg` (no prefix) |
| `self.print_table(title, headers, *rows)` | Formatted table |

---

## Part 3: TLV Protocol Primer

### Tag Construction

```python
tag = tlv_custom_tag(pool, base, call)
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `pool` | `API_CALL_STATIC` | For plugin API calls |
| `base` | `TAB_BASE` | Always `2` for plugins |
| `call` | `API_CALL`, `API_CALL + 1`, ... | Call number starting at 1 |

### Type Construction

```python
type = tlv_custom_type(parent_type, base, child)
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| `parent_type` | `TLV_TYPE_STRING`, `TLV_TYPE_INT`, `TLV_TYPE_BYTES`, `TLV_TYPE_GROUP` | Data type |
| `base` | `TAB_BASE` | Always `2` for plugins |
| `child` | `API_TYPE`, `API_TYPE + 1`, ... | Type number starting at 1 |

### Available TLV Types

| Parent Type | Python Method | C Function |
|-------------|-------------|------------|
| `TLV_TYPE_STRING` | `get_string()` | `tlv_pkt_add_string` / `tlv_pkt_get_string` |
| `TLV_TYPE_INT` | `get_int()` | `tlv_pkt_add_u32` / `tlv_pkt_get_u32` |
| `TLV_TYPE_BYTES` | `get_raw()` | `tlv_pkt_add_bytes` / `tlv_pkt_get_bytes` |
| `TLV_TYPE_GROUP` | `get_tlv()` | `tlv_pkt_add_tlv` |
| `TLV_TYPE_LONG` | `get_long()` | For 64-bit integers |

### Status Codes

| Constant | Value | Meaning |
|----------|-------|---------|
| `TLV_STATUS_SUCCESS` | 1 | Call succeeded |
| `TLV_STATUS_FAIL` | 2 | Call failed |
| `TLV_STATUS_NOT_IMPLEMENTED` | 4 | Call not implemented |
| `TLV_STATUS_ENOENT` | 7 | Resource not found |

---

## Part 4: Building

### Adding to CMakeLists.txt

Create your plugin directory and source file:

```
plugins/myplugin/myplugin.c
```

The CMake build system automatically discovers plugins in `plugins/`:

```cmake
file(GLOB PLUGIN_DIRS plugins/*)
```

POSIX plugins are automatically built as static-pie executables.

### Build Commands

```bash
# Build dependencies first
make TARGET=x86_64-linux-musl

# Build with plugins
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/x86_64-linux-musl.cmake \
      -DMAIN=ON -DPLUGINS=ON -B build
cmake --build build
```

Compiled plugins are automatically placed in `pwny/tabs/<platform>/<arch>/`.

---

## Part 5: Plugin Loading Flow

### How plugins are loaded at runtime:

```
1. User types: load myplugin
         │
2. Console finds: pwny/plugins/<platform>/myplugin.py
         │
3. Python imports HatSploitPlugin class
         │
4. Loader reads: pwny/tabs/<platform>/<arch>/myplugin (binary blob)
         │
5. Binary sent to implant via BUILTIN_ADD_TAB_BUFFER
         │
6. Implant loads binary via `tabs_add_dll()` (dlopen / exec)
         │
7. Plugin init runs, API calls registered
         │
8. Python wrapper's commands added to console
         │
9. User can now use the plugin's commands
```

### Pipes (Streaming Data)

Some plugins use **pipes** for streaming data (camera, microphone, screen):

```python
# Define a pipe type
MYPLUGIN_PIPE = tlv_custom_pipe(PIPE_STATIC, TAB_BASE, PIPE_TYPE)
```

```c
// C side — register pipe handler
api_pipe_register(MYPLUGIN_PIPE, my_pipe_handler);
```

Pipes are bidirectional and use a heartbeat mechanism for liveness checking.

---

## Example: Complete Plugin

See the test plugin as a reference implementation:

- **C source:** `plugins/test/test.c`
- **Python wrapper:** `plugins/test/test.py` and `pwny/plugins/macos/test.py`

---

## See Also

- [Building](building.md) — compiling from source
- [Commands Reference](commands.md) — cross-platform commands
