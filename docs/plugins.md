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
    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}
```

**NOTE:** All functions should return `tlv_pkt_t *` and have `c2_t *` as an argument (`c2_t *` is an instance of the C2 handler).

All Pwny plugins should have this code as a `main(void)` function.

```c
int main(void)
{
    tab_t *tab;

    tab = tab_create();
    tab_setup(tab);

    /* Your TAB API calls registration */

    tab_start(tab);
    tab_destroy(tab);

    return 0;
}
```

If you have one or more functions available, you should replace `/* Your TAB API calls registration */` with this code:

```c
tab_register_call(tab, TEST, test);
```

Where `TEST` is a function TLV tag and `test` is a function.

## How does it work?

Here is how Pwny loads TAB (plugin):

**1.** Receive TAB (plugin) executable from C2.
**2.** Copy TAB and create a child process.
**3.** Execute TAB inside the child process.
**4.** Establish IPC (Inter Process Communication) using file descriptors.

![diagram](/docs/tabs.png)

On the C2 side, either `BUILTIN_ADD_TAB_DISK` being called or `BUILTIN_ADD_TAB_BUFFER`.

* `BUILTIN_ADD_TAB_DISK` - Add TAB from file on disk.
* `BUILTIN_ADD_TAB_BUFFER` - Add TAB from buffer. (stealth, in-memory loading)
