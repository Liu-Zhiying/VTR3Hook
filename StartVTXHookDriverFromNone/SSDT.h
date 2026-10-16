#ifndef SSDT_H
#define SSDT_H

#include <ntddk.h>

/* 未文档化结构，WRK 里有同样定义 */
typedef struct _KSYSTEM_SERVICE_TABLE {
    PULONG_PTR ServiceTableBase;        // 00
    PULONG_PTR ServiceCounterTableBase; // 08
    ULONG      NumberOfServices;        // 10  ← 我们要的“表长度”
    PUCHAR     ParamTableBase;          // 18
} KSYSTEM_SERVICE_TABLE, * PKSYSTEM_SERVICE_TABLE;

PVOID GetSubFunctionInSSDTByIndex(PVOID pSSDT, UINT32 index);
UINT32 GetSubFunctionCountInSSDT(PVOID pSSDT);

#endif