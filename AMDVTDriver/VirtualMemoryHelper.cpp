#include "VirtualMemoryHelper.h"

#pragma code_seg("PAGE")
VOID TouchReadonlyCowPageEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtProtectVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	HookFunctionManager::PNtProtectVirtualMemory pNtProtectVirtualMemory =
		(HookFunctionManager::PNtProtectVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtProtectVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PVOID pPage = StartContext;
	SIZE_T size = 1;
	ULONG oldProtect = 0;
	NTSTATUS status = pNtProtectVirtualMemory(NtCurrentProcess(), &pPage, &size, PAGE_EXECUTE_READWRITE, &oldProtect);

	if (!NT_SUCCESS(status))
		PsTerminateSystemThread(status);

	__try
	{
		ProbeForRead(pPage, size, 1);
		ProbeForWrite(pPage, size, 1);
		//触发写时复制
		CHAR temp = *((volatile CHAR*)pPage);
		*((volatile CHAR*)pPage) = temp;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
	}

	pPage = StartContext;
	size = 1;

	pNtProtectVirtualMemory(NtCurrentProcess(), &pPage, &size, oldProtect, &oldProtect);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

#pragma code_seg("PAGE")
VOID LockVirtualMemoryEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtLockVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	HookFunctionManager::PNtLockVirtualMemory pNtLockVirtualMemory =
		(HookFunctionManager::PNtLockVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtLockVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	SIZE_T size = 1;

	PsTerminateSystemThread(pNtLockVirtualMemory(NtCurrentProcess(), &StartContext, &size, 1));
}

#pragma code_seg("PAGE")
VOID UnlockVirtualMemoryEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtUnlockVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	HookFunctionManager::PNtUnlockVirtualMemory pNtUnlockVirtualMemory =
		(HookFunctionManager::PNtUnlockVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtUnlockVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	SIZE_T size = 1;

	PsTerminateSystemThread(pNtUnlockVirtualMemory(NtCurrentProcess(), &StartContext, &size, 1));
}

#pragma code_seg("PAGE")
NTSTATUS TouchReadonlyCowPage(_In_ PVOID pPage, _In_ PEPROCESS pProcess)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, TouchReadonlyCowPageEntry, pPage);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}

#pragma code_seg("PAGE")
NTSTATUS LockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, LockVirtualMemoryEntry, pPage);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}

#pragma code_seg("PAGE")
NTSTATUS UnlockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, UnlockVirtualMemoryEntry, pPage);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}
