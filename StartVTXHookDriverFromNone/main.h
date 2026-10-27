#ifndef MAIN_H
#define MAIN_H

#define DRIVER_USE

#include "VTX.h"
#include "Hook.h"
#include "PageTable.h"
#include "Basic.h"
#include "SSDT.h"
#include "../VTR3HookLib/CtrlDefine.h"
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
public:
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

	typedef enum _SYSDBG_COMMAND {
		SysDbgQueryMemory,                    // 0
		SysDbgQuerySpecialMemory,             // 1
		SysDbgReadMemory,                     // 2  读内核虚拟内存
		SysDbgWriteMemory,                    // 3  写内核虚拟内存
		SysDbgReadPhysicalMemory,             // 4  读物理内存
		SysDbgWritePhysicalMemory,            // 5  写物理内存
		SysDbgReadControlSpace,               // 6  读控制空间（kd 数据块）
		SysDbgWriteControlSpace,              // 7
		SysDbgReadIoSpace,                    // 8  读 I/O 端口空间
		SysDbgWriteIoSpace,                   // 9
		SysDbgReadMsr,                        // 10 读 MSR
		SysDbgWriteMsr,                       // 11
		SysDbgReadBusData,                    // 12
		SysDbgWriteBusData,                   // 13
		SysDbgCheckLowMemory,                 // 14
		SysDbgEnableKernelDebugger,           // 15 运行时启用 kd
		SysDbgDisableKernelDebugger,          // 16 运行时禁用 kd
		SysDbgGetAutoKdEnable,                // 17
		SysDbgSetAutoKdEnable,                // 18
		SysDbgGetPrintBufferSize,             // 19
		SysDbgSetPrintBufferSize,             // 20
		SysDbgGetKdUmExceptionEnable,         // 21
		SysDbgSetKdUmExceptionEnable,         // 22
		SysDbgGetTriageDump,                  // 23
		SysDbgGetKdBlockEnable,               // 24
		SysDbgSetKdBlockEnable,               // 25
		SysDbgRegisterForUmBreakInfo,         // 26
		SysDbgGetUmBreakPid,                  // 27
		SysDbgClearUmBreakPid,                // 28
		SysDbgGetUmAttachPid,                 // 29
		SysDbgClearUmAttachPid,               // 30
		SysDbgGetLiveKernelDump,              // 31 Win10+ 触发 live dump
		SysDbgGetKdPullModeEnable,            // 32 较新版本
		SysDbgSetKdPullModeEnable,            // 33
		SysDbgMaxCommand
	} SYSDBG_COMMAND;

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
	typedef NTSTATUS(NTAPI* PNtSystemDebugControl)(
		__in SYSDBG_COMMAND Command,          // 要执行的操作
		__in_opt PVOID InputBuffer,           // 输入参数（结构体，视命令而定）
		__in ULONG InputBufferLength,
		__out_opt PVOID OutputBuffer,
		__in ULONG OutputBufferLength,
		__out_opt PULONG ReturnLength);
	typedef NTSTATUS(NTAPI* PNtLockVirtualMemory)(
		_In_ HANDLE ProcessHandle,        // 目标进程，NtCurrentProcess()
		_Inout_ PVOID* BaseAddress,       // 区域基址，按页向下对齐
		_Inout_ PSIZE_T RegionSize,       // 大小，会被向上取整到页边界
		_In_ ULONG MapType);              // MAP_PROCESS(1) 或 MAP_SYSTEM(2)
	typedef NTSTATUS(NTAPI* PNtUnlockVirtualMemory)(
		_In_ HANDLE ProcessHandle,        // 目标进程，NtCurrentProcess()
		_Inout_ PVOID* BaseAddress,       // 区域基址，按页向下对齐
		_Inout_ PSIZE_T RegionSize,       // 大小，会被向上取整到页边界
		_In_ ULONG MapType);              // MAP_PROCESS(1) 或 MAP_SYSTEM(2)
	typedef NTSTATUS(NTAPI* PNtProtectVirtualMemory)(
		_In_ HANDLE ProcessHandle,        // 目标进程，NtCurrentProcess()
		_Inout_ PVOID* BaseAddress,       // 区域基址，按页向下对齐
		_Inout_ PSIZE_T RegionSize,       // 大小，会被向上取整到页边界
		_In_ ULONG NewProtect,            // 新的保护属性
		_Out_ PULONG OldProtect);         // 返回旧的保护属性
private:
	inline static PNtCreateProcess pOldNtCreateProcess = NULL;
	inline static PNtCreateProcess pNtCreateProcessCaller = NULL;
	
	inline static PNtCreateFile pOldNtCreateFile = NULL;
	inline static PNtCreateFile pNtCreateFileCaller = NULL;

	inline static PNtQuerySystemInformation pOldNtQuerySystemInformation = NULL;
	inline static PNtQuerySystemInformation pNtQuerySystemInformationCaller = NULL;

	inline static PNtSystemDebugControl pOldNtSystemDebugControl = NULL;
	inline static PNtSystemDebugControl pNtSystemDebugControlCaller = NULL;

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
			//KdPrint(("有程序检测测试模式, pid = %llu！\n", PsGetCurrentProcessId()));
			if (SystemInformation != NULL &&
				SystemInformationLength >= sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) &&
				NT_SUCCESS(status)) {

				//KdPrint(("测试模式检测已经HOOK！\n"));

				PSYSTEM_CODEINTEGRITY_INFORMATION pInfo =
					(PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation;

				// 3. 清除 TESTSIGNING 标志位，伪装测试模式未启用
				pInfo->CodeIntegrityOptions &= ~CODEINTEGRITY_OPTION_TESTSIGN;
			}
		}

		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			//KdPrint(("有程序检测内核调试, pid = %llu！\n", PsGetCurrentProcessId()));

			if (SystemInformation != NULL &&
				SystemInformationLength >= sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION) &&
				NT_SUCCESS(status)) {

				//KdPrint(("内核调试检测已经HOOK！\n"));

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

	static NTSTATUS NTAPI NtSystemDebugControlHandler(
		__in SYSDBG_COMMAND Command,          // 要执行的操作
		__in_opt PVOID InputBuffer,           // 输入参数（结构体，视命令而定）
		__in ULONG InputBufferLength,
		__out_opt PVOID OutputBuffer,
		__in ULONG OutputBufferLength,
		__out_opt PULONG ReturnLength)
	{
		//KdPrint(("有程序使用内核调试服务, pid = %llu！\n", PsGetCurrentProcessId()));
		//KdPrint(("内核调试服务已经HOOK！\n"));
		UNREFERENCED_PARAMETER(Command);
		UNREFERENCED_PARAMETER(InputBuffer);
		UNREFERENCED_PARAMETER(InputBufferLength);
		UNREFERENCED_PARAMETER(OutputBuffer);
		UNREFERENCED_PARAMETER(OutputBufferLength);
		UNREFERENCED_PARAMETER(ReturnLength);
		return STATUS_DEBUGGER_INACTIVE;
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
	static UINT32 GetSyscallIndex(const char* pFunctionName);
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
		
		index = GetSyscallIndex("NtCreateFile");
		
		pOldNtCreateFile = (PNtCreateFile)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtCreateFileCaller = (PNtCreateFile)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtCreateFile);

		record.pOriginVirtAddr = pOldNtCreateFile;
		record.pGotoVirtAddr = NtCreateFileHandler;

		//pGlobalManager->eptHookManager.AddHook(record);

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

		index = GetSyscallIndex("NtSystemDebugControl");

		pOldNtSystemDebugControl = (PNtSystemDebugControl)GetSubFunctionInSSDTByIndex(pSSDT, index);
		pNtSystemDebugControlCaller = (PNtSystemDebugControl)pGlobalManager->functionCallerManager.GetFunctionCaller(pOldNtSystemDebugControl);

		record.pOriginVirtAddr = pOldNtSystemDebugControl;
		record.pGotoVirtAddr = NtSystemDebugControlHandler;

		//pGlobalManager->eptHookManager.AddHook(record);
	}
#pragma code_seg("PAGE")
	static void UnhookSSDT(GlobalManager* pGlobalManager)
	{
		pGlobalManager->eptHookManager.RemoveHook(pOldNtCreateProcess);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtCreateProcess);

		pGlobalManager->eptHookManager.RemoveHook(pOldNtCreateFile);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtCreateFile);

		pGlobalManager->eptHookManager.RemoveHook(pOldNtQuerySystemInformation);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtQuerySystemInformation);

		pGlobalManager->eptHookManager.RemoveHook(pOldNtSystemDebugControl);
		pGlobalManager->functionCallerManager.RemoveFunctionCaller(pOldNtSystemDebugControl);
	}
};

extern VOID* pKeServiceDescriptorTable;

#endif
