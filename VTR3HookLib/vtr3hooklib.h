#ifndef VTR3HOOKLIB_H
#define VTR3HOOKLIB_H

#include <Windows.h>

bool InitHookDriver();
void DeinitHookDriver();

void StartVMAndHook();
void StopVMAndUnHook();

void HookFunction(PVOID pOriginAddr, PVOID pGotoAddr, UINT64 processId = GetCurrentProcessId());
void UnhookFunction(PVOID pOriginAddr, PVOID pGotoAddr, UINT64 processId = GetCurrentProcessId());

#endif // !

