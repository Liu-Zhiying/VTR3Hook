#include "syscall_reader.h"
#include <Windows.h>

// 以十六进制打印机器码
UINT32 DumpSyscaallIndex(LPCVOID addr)
{
    const BYTE* code = (const BYTE*)addr;

    UINT32 result = -1;

    SIZE_T index = 0;

    while (true)
    {
        if (code[index] == 0xC3 && code[index + 1] == 0xCC)
            break;

        if (code[index] == 0xCC && code[index + 1] == 0xCC)
            break;

        if (code[index] == 0x0F && code[index + 1] == 0x05 && code[index + 2] == 0xC3)
        {
            do
            {
                if (code[index] == 0xB8)
                    result = *((UINT32*)(code + index + 1));
            } while (--index);
            break;
        }

        ++index;
    }

    return result;
}


std::vector<SyscallIdx> ReadSyscall()
{
    HMODULE hMod = GetModuleHandleA("ntdll.dll");

    if (hMod == NULL) return {};

    // 1. 定位 DOS 头 -> NT 头 -> 导出目录
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return {};

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return {};

    DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0) return {};

    PIMAGE_EXPORT_DIRECTORY pExp =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + expRva);

    if (pExp == NULL) return {};

    DWORD* names = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);
    DWORD count = pExp->NumberOfNames;   // 按名字导出的函数数量

    std::vector<SyscallIdx> result;

    for (DWORD i = 0; i < count; i++) {
        const char* fnName = (const char*)((BYTE*)hMod + names[i]);
        FARPROC addr = GetProcAddress(hMod, fnName);
        if (addr != NULL) {
            UINT32 index = DumpSyscaallIndex(addr);
            if (index != -1)
            {
                SyscallIdx item = { fnName, index};
                result.push_back(item);
            }
        }
    }

    return result;
}
