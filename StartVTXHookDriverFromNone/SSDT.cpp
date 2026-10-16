#include "SSDT.h"

PVOID GetSubFunctionInSSDTByIndex(PVOID pSSDT, UINT32 index)
{
    /* 强制转换成未文档化结构指针 */
    PKSYSTEM_SERVICE_TABLE ssdt = (PKSYSTEM_SERVICE_TABLE)pSSDT;

    ULONG Count = ssdt->NumberOfServices;          // 表长度
    PULONG_PTR Table = ssdt->ServiceTableBase;     // 表基址

    if (Count < index)
        return NULL;

    ULONG Raw = ((PULONG)Table)[index];

    if (Raw == 0) return NULL;

    ULONG64 FuncRVA = Raw >> 4;
    ULONG64 FuncVA = (ULONG64)Table + FuncRVA;

    return (PVOID)FuncVA;
}

inline UINT32 GetSubFunctionCountInSSDT(PVOID pSSDT)
{
    return ((PKSYSTEM_SERVICE_TABLE)pSSDT)->NumberOfServices;
}
