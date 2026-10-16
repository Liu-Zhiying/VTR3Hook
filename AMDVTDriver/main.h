#ifndef MAIN_H
#define MAIN_H

#include <ntddk.h>
#include <wdm.h>
#include <stdio.h>
#include <intrin.h>
#include "SVM.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"
#include "../StartVTXHookDriverFromNone/CtrlDefine.h"
#include "SSDT.h"

constexpr ULONG MAIN_TAG = MAKE_TAG('m', 'a', 'i', ' ');

//二选一取消注释，测试驱动的两个功能
#define TEST_NPT_HOOK
//#define TEST_MSR_HOOK

//是否测试NPT HOOK删除
//#define TEST_NPT_HOOK_REMOVE

class GlobalManager : public IManager
{
public:
	SVMManager svmManager;
#if defined(TEST_NPT_HOOK)
	NptHookManager nptHookManager;
	FunctionCallerManager functionCallerManager;
#else
	MsrHookManager<1> msrHookManager;
#endif

#if defined(TEST_NPT_HOOK)
	void HookApi();
#else
	void SetMsrHookParameters();
	void EnableMsrHook();
#endif
	
	virtual NTSTATUS Init() override;
	virtual void Deinit() override;
	virtual ~GlobalManager();
};

class HookFunctionManager
{
	typedef NTSTATUS(NTAPI* PNtCreateProcess)(
		_Out_ PHANDLE				ProcessHandle,
		_In_  ACCESS_MASK			DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_  HANDLE				ParentProcess,
		_In_  BOOLEAN				InheritObjectTable,
		_In_opt_ HANDLE				SectionHandle,
		_In_opt_ HANDLE				DebugPort,
		_In_opt_ HANDLE				ExceptionPort);
	typedef NTSTATUS(NTAPI* PNtCreateFile)(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_ PLARGE_INTEGER AllocationSize,
		_In_ ULONG FileAttributes,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		_In_ ULONG EaLength);
	inline static PNtCreateProcess pOldNtCreateProcess = NULL;
	inline static PNtCreateProcess pNtCreateProcessCaller = NULL;

	inline static PNtCreateFile pOldNtCreateFile = NULL;
	inline static PNtCreateFile pNtCreateFileCaller = NULL;

	inline static unsigned char buffer[sizeof(KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>)];
	static NTSTATUS NTAPI NtCreateProcessHandler(
		_Out_ PHANDLE				ProcessHandle,
		_In_  ACCESS_MASK			DesiredAccess,
		_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
		_In_  HANDLE				ParentProcess,
		_In_  BOOLEAN				InheritObjectTable,
		_In_opt_ HANDLE				SectionHandle,
		_In_opt_ HANDLE				DebugPort,
		_In_opt_ HANDLE				ExceptionPort)
	{
		NTSTATUS status = pNtCreateProcessCaller(
			ProcessHandle,
			DesiredAccess,
			ObjectAttributes,
			ParentProcess,
			InheritObjectTable,
			SectionHandle,
			DebugPort,
			ExceptionPort);

		KdPrint(("NtCreateProcess called!\n"));

		return status;
	}

	static NTSTATUS NTAPI NtCreateFileHandler(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_ PLARGE_INTEGER AllocationSize,
		_In_ ULONG FileAttributes,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		_In_ ULONG EaLength)
	{
		NTSTATUS status = pNtCreateFileCaller(
			FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);

		KdPrint(("NtCreateFile called!\n"));

		return status;
	}

#pragma data_seg()
	inline static bool isInited = false;
#pragma data_seg()
public:

#pragma code_seg("PAGE")
	static NTSTATUS Init()
	{
		if (!isInited)
		{
			CallConstructor((KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer);
			isInited = true;
		}
		return STATUS_SUCCESS;
	}
#pragma code_seg("PAGE")
	static void Deinit()
	{
		if (isInited)
		{
			CallDestroyer((KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer);
			isInited = false;
		}
	}
	static void SetSyscallIndex(char* pFunctionName, UINT32 index);
	static UINT32 GetSyscallIndex(char* pFunctionName);
#pragma code_seg("PAGE")
	static void HookSSDT(PVOID pSSDT, GlobalManager* pGlobalManager)
	{
		UNREFERENCED_PARAMETER(pSSDT);
		UNREFERENCED_PARAMETER(pGlobalManager);

		NptHookRecord record = {};

		UINT32 index = GetSyscallIndex("NtCreateProcess");

		pOldNtCreateProcess = (PNtCreateProcess)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateProcessCaller = (PNtCreateProcess)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateProcess);

		record.pOriginVirtAddr = pOldNtCreateProcess;
		record.pGotoVirtAddr = NtCreateProcessHandler;

		pGlobalManager->nptHookManager.AddHook(record);
		
		index = GetSyscallIndex("NtCreateFile");

		pOldNtCreateFile = (PNtCreateFile)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateFileCaller = (PNtCreateFile)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateFile);

		record.pOriginVirtAddr = pOldNtCreateFile;
		record.pGotoVirtAddr = NtCreateFileHandler;

		pGlobalManager->nptHookManager.AddHook(record);
	}
#pragma code_seg("PAGE")
	static void UnhookSSDT(GlobalManager* pGlobalManager)
	{
		pGlobalManager->nptHookManager.RemoveHook(NtCreateProcessHandler);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pNtCreateProcessCaller);
		pNtCreateProcessCaller = NULL;
	}
};

#endif
