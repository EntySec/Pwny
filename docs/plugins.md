# Pwny Plugins

Pwny plugins are dynamic extensions that are used to extend basic Pwny functionality. They are represented as a separate binary executable which executes in the memory as a child process of Pwny and communicates with it using file descriptors.

**NOTE:** Plugins are called TABs within the code (TAB - The Additional Bundle).

## Writing plugin

Firstly, include these headers:

```c
#include <tab.h>
#include <api.h>
#include <c2.h>
#include <tlv.h>
#include <tlv_types.h>
#include <console.h>
```

Then you should specify TLV tag for each of the plugin functions.

```c
#define TEST \
        TLV_TYPE_CUSTOM(API_CALL_DYNAMIC, \
                        TAB_BASE, \
                        API_CALL)
```

`API_CALL_DYNAMIC` and `TAB_BASE` should be left unchanged. However, for all further tags you should write `API_CALL + N` where `N` is a number of function starting with `1` (e.g. `API_CALL + 1`, `API_CALL + 2` and so on)

Then declare your function. You can find all the necessary constants and tools in `include/` or you can refer to the TLV and C2 docs.

```c
static tlv_pkt_t *test(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_SUCCESS);
}
```

**NOTE:** All functions should return `tlv_pkt_t *` and have `c2_t *` as an argument (`c2_t *` is an instance of the C2 handler).

All Pwny plugins should have this code as a `main(void)` function.

```c
int main(void)
{
    c2_t *c2;

    c2 = c2_create(0, STDIN_FILENO, NULL);

    /* Your C2 API calls registration */

    tab_console_loop(c2);
    c2_destroy(c2);

    return 0;
}
```

If you have one or more functions available, you should replace `/* Your C2 API calls registration */` with this code:

```c
api_call_register(&c2->dynamic.api_calls, TEST, test);
```

Where `TEST` is a function TLV tag and `test` is a function.

## How it works?

Here is how Pwny loads TAB (plugin):

**1.** Receive TAB (plugin) executable from C2.
**2.** Copy TAB and create a child process.
**3.** Execute TAB inside the child process.
**4.** Establish IPC (Inter Process Communication) by file descriptors.

![diagram](https://github.com/EntySec/Pwny/tree/main/docs/tabs.png)

On the C2 side, either `BUILTIN_ADD_TAB_DISK` being called or `BUILTIN_ADD_TAB_BUFFER`.

* `BUILTIN_ADD_TAB_DISK` - Add TAB from file on disk.
* `BUILTIN_ADD_TAB_BUFFER` - Add TAB from buffer. (steath, in-memory loading)

## Quiting TAB

Pwny has a specific conatant `TAB_TERM` which is being sent to the TAB to make it shutdown. On the C2 side, all you need to do is to call `BUILTIN_DELETE_TAB` from Pwny Builtins.
