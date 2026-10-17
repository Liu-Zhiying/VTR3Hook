#ifndef MAIN_H
#define MAIN_H

#include "VTX.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"
#include "SSDT.h"
#include "CtrlDefine.h"
#include <stdio.h>
#include <intrin.h>

constexpr ULONG MAIN_TAG = MAKE_TAG('m', 'a', 'i', ' ');

//二选一取消注释，测试驱动的两个功能
#define TEST_EPT_HOOK
//#define TEST_MSR_HOOK

//是否测试NPT HOOK删除
//#define TEST_NPT_HOOK_REMOVE

class GlobalManager : public IManager
{
public:
	VTXManager vtxManager;
#if defined(TEST_EPT_HOOK)
	EptHookManager eptHookManager;
	FunctionCallerManager functionCallerManager;
#else
	MsrHookManager<1> msrHookManager;
#endif

#if defined(TEST_EPT_HOOK)
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
	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemCrashDumpStateInformation = 34,
		SystemKernelDebuggerInformation = 35, // 用于检测内核调试器
		SystemContextSwitchInformation = 36,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45,
		SystemCodeIntegrityInformation = 103
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
		BOOLEAN KernelDebuggerEnabled;      // 偏移 0x00
		BOOLEAN KernelDebuggerNotPresent;   // 偏移 0x01
	} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
		ULONG Length;
		ULONG CodeIntegrityOptions;
	} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

	// 标志位
	static constexpr UINT64 CODEINTEGRITY_OPTION_TESTSIGN = 0x02;

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
	typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,
			PVOID                    SystemInformation,
			ULONG                    SystemInformationLength,
			PULONG                   ReturnLength);
	inline static PNtCreateProcess pOldNtCreateProcess = NULL;
	inline static PNtCreateProcess pNtCreateProcessCaller = NULL;
	

	inline static PNtCreateFile pOldNtCreateFile = NULL;
	inline static PNtCreateFile pNtCreateFileCaller = NULL;

	inline static PNtQuerySystemInformation pOldNtQuerySystemInformation = NULL;
	inline static PNtQuerySystemInformation pNtQuerySystemInformationCaller = NULL;

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

		//KdPrint(("NtCreateProcess called!\n"));

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

		//KdPrint(("NtCreateFile called!\n"));

		return status;
	}

	static NTSTATUS NTAPI NtQuerySystemInformationHandler(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength)
	{
		NTSTATUS status = pNtQuerySystemInformationCaller(
			SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength);

		if (SystemInformationClass == SystemCodeIntegrityInformation) {
			KdPrint(("有程序检测测试模式, pid = %llu！\n", PsGetCurrentProcessId()));
			if (SystemInformation != NULL &&
				SystemInformationLength >= sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) &&
				NT_SUCCESS(status)) {

				KdPrint(("测试模式检测已经HOOK！\n"));

				PSYSTEM_CODEINTEGRITY_INFORMATION pInfo =
					(PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation;

				// 3. 清除 TESTSIGNING 标志位，伪装测试模式未启用
				pInfo->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;
			}
		}

		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			KdPrint(("有程序检测内核调试, pid = %llu！\n", PsGetCurrentProcessId()));

			if (SystemInformation != NULL &&
				SystemInformationLength >= sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION) &&
				NT_SUCCESS(status)) {

				KdPrint(("内核调试检测已经HOOK！\n"));

				PSYSTEM_KERNEL_DEBUGGER_INFORMATION debuggerInfo =
					(PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

				// 3. 篡改返回值：伪装成没有调试器
				debuggerInfo->KernelDebuggerEnabled = FALSE;   // 调试器未启用
				debuggerInfo->KernelDebuggerNotPresent = TRUE; // 调试器不存在

				// 如果 ReturnLength 有效，也可以修正它
				if (ReturnLength) {
					*ReturnLength = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION);
				}
			}
		}

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
		
		EptHookRecord record = {};
		
		UINT32 index = GetSyscallIndex("NtCreateProcess");

		pOldNtCreateProcess = (PNtCreateProcess)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateProcessCaller = (PNtCreateProcess)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateProcess);

		record.pOriginVirtAddr = pOldNtCreateProcess;
		record.pGotoVirtAddr = NtCreateProcessHandler;

		//pGlobalManager->eptHookManager.AddHook(record);
		/*
		index = GetSyscallIndex("NtCreateFile");
		
		pOldNtCreateFile = (PNtCreateFile)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateFileCaller = (PNtCreateFile)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateFile);

		record.pOriginVirtAddr = pOldNtCreateFile;
		record.pGotoVirtAddr = NtCreateFileHandler;

		pGlobalManager->eptHookManager.AddHook(record);
		*/

		// IOCTL 派发时当前就是用户进程上下文
		PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)0x7FFE0000);
		if (!pa.QuadPart) return;

		PKUSER_SHARED_DATA pUserData = (PKUSER_SHARED_DATA)MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
		if (pUserData == NULL) return;

		pUserData->KdDebuggerEnabled = FALSE;

		MmUnmapIoSpace(pUserData, PAGE_SIZE);

		index = GetSyscallIndex("NtQuerySystemInformation");

		pOldNtQuerySystemInformation = (PNtQuerySystemInformation)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtQuerySystemInformationCaller = (PNtQuerySystemInformation)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtQuerySystemInformation);

		record.pOriginVirtAddr = pOldNtQuerySystemInformation;
		record.pGotoVirtAddr = NtQuerySystemInformationHandler;

		pGlobalManager->eptHookManager.AddHook(record);
	}
#pragma code_seg("PAGE")
	static void UnhookSSDT(GlobalManager* pGlobalManager)
	{
		//pGlobalManager->eptHookManager.RemoveHook(NtCreateProcessHandler);
		//pGlobalManager->functionCallerManager.RemoveFunctionCaller(NtCreateFileHandler);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(NtQuerySystemInformationHandler);
		pNtCreateProcessCaller = NULL;
	}
};


#endif
