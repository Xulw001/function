#include "allocate/allocate.h"
#ifndef _WIN32
#include <stdio.h>
#else
#include <Windows.h>
#endif
#ifndef _WIN32
void __attribute__((constructor)) __init(void) { createHeapManage(); }

void __attribute__((destructor)) __fini(void) { destoryHeapManage(); }

#else
BOOL __stdcall DLLMain(HMODULE hModule, DWORD ul_reason_for_call,
                       LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      createHeapManage();
      break;
    case DLL_PROCESS_DETACH:
      destoryHeapManage();
      break;
    default:
      break;
  }
}
#endif
