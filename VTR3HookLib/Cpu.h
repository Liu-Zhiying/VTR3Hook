#ifndef CPU_H
#define CPU_H

#include <Windows.h>

void CPUString(char* outputString);
bool IsAMDCPU();
bool IsIntelCPU();

extern "C" void _vmcall(ULONG_PTR* rax, ULONG_PTR* rbx, ULONG_PTR* rcx, ULONG_PTR* rdx);
extern "C" void _vmmcall(ULONG_PTR* rax, ULONG_PTR* rbx, ULONG_PTR* rcx, ULONG_PTR* rdx);

bool IntelCpuIsInVirtualization();
bool AMDCpuIsInVirtualization();

#endif
