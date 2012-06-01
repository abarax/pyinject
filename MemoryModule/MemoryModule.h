#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER
# define DLLIMPORT __declspec (dllexport)

#include <Windows.h>

typedef void *HMEMORYMODULE;

#ifdef __cplusplus
extern "C" {
#endif

DLLIMPORT HMEMORYMODULE MemoryLoadLibrary(const void *);

DLLIMPORT FARPROC MemoryGetProcAddress(HMEMORYMODULE, const char *);

DLLIMPORT void MemoryFreeLibrary(HMEMORYMODULE);


#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
