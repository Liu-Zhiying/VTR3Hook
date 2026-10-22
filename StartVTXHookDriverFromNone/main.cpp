#include "main.h"

extern "C"
_Must_inspect_result_
_IRQL_requires_max_(APC_LEVEL)
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS* Process
);

#pragma data_seg()
VOID* pNtosKrnlBase = NULL;
VOID* pKeServiceDescriptorTable = NULL;
PTR_TYPE DirectoryTableBaseRVA;
GlobalManager* pGlobalManager = NULL;
#pragma data_seg()

#pragma code_seg("PAGE")
NTSTATUS DriverIOHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	PAGED_CODE();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
NTSTATUS DriverControlHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	PAGED_CODE();

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS           Status = STATUS_SUCCESS;
	ULONG_PTR          Info = 0;

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_SET_KERNEL_RVA:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		//ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		//设置SSDT的地址

		if (inLen == sizeof(KernelRvaInfo))
		{
			KernelRvaInfo* pInfo = (KernelRvaInfo*)Irp->AssociatedIrp.SystemBuffer;

			VOID* pZwCreateFile = ZwCreateFile;

			pNtosKrnlBase = (VOID*)((PCHAR)pZwCreateFile - (ULONG_PTR)pInfo->ZwCreateFileRVA);
			pKeServiceDescriptorTable = (PCHAR)pNtosKrnlBase + (ULONG_PTR)pInfo->KeServiceDescriptorTableRVA;
			DirectoryTableBaseRVA = (PTR_TYPE)pInfo->DirectoryTableBaseRVA;

			Info = sizeof(KernelRvaInfo);
		}
		break;
	}

	case IOCTL_START_VM_AND_HOOK:
	{
		//开始进行虚拟化
		pGlobalManager->vtxManager.EnterVirtualization();

		//启用进程HOOK
		pGlobalManager->eptHookManager.EnableProcessHook(DirectoryTableBaseRVA);

		//HookFunctionManager::HookSSDT(pKeServiceDescriptorTable, pGlobalManager);

		Info = 0;                                              // 纯写入，无返回长度
		break;
	}

	case IOCTL_STOP_VM_AND_UNHOOK:
	{
		//HookFunctionManager::UnhookSSDT(pGlobalManager);

		//禁用进程HOOK
		pGlobalManager->eptHookManager.DisableProcessHook();

		//开始退出虚拟化
		pGlobalManager->vtxManager.LeaveVirtualization();

		Info = 0;
		break;
	}
	case IOCTL_SET_SYSCALL_INDEX:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入

		if (inLen == sizeof(SyscallIndexIn))
		{
			SyscallIndexIn* pInfo = (SyscallIndexIn*)Irp->AssociatedIrp.SystemBuffer;

			HookFunctionManager::SetSyscallIndex(pInfo->functionName, pInfo->index);

			Info = inLen;
		}
		break;
	}
	case IOCTL_ADD_HOOK:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		//ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		if (inLen == sizeof(EptProcessHookRecordIn))
		{
			EptProcessHookRecordIn* pInfo = (EptProcessHookRecordIn*)Irp->AssociatedIrp.SystemBuffer;

			EptProcessHookRecord record = {};

			record.pOriginVirtAddr = pInfo->pOriginVirtAddr;
			record.pGotoVirtAddr = pInfo->pGotoVirtAddr;

			PEPROCESS pProcess = NULL;

			PsLookupProcessByProcessId((HANDLE)pInfo->processId, &pProcess);

			if (pProcess == NULL)
				return STATUS_UNSUCCESSFUL;

			pGlobalManager->eptHookManager.AddProcessHook(record, pProcess);

			ObDereferenceObject(pProcess);

			Info = inLen;
		}
		break;
	}
	case IOCTL_REMOVE_HOOK:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		//ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		if (inLen == sizeof(EptProcessHookRecordIn))
		{
			EptProcessHookRecordIn* pInfo = (EptProcessHookRecordIn*)Irp->AssociatedIrp.SystemBuffer;

			PEPROCESS pProcess = NULL;

			PsLookupProcessByProcessId((HANDLE)pInfo->processId, &pProcess);

			if (pProcess == NULL)
				return STATUS_UNSUCCESSFUL;

			pGlobalManager->eptHookManager.RemoveProcessHook(pInfo->pOriginVirtAddr, pGlobalManager->eptHookManager.GetProcessCr3(pProcess));

			ObDereferenceObject(pProcess);

			Info = inLen;
		}
		break;
	}
	case IOCTL_GET_PHYSICAL_ADDRESS:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		if (inLen == sizeof(PVOID) && outLen == sizeof(PVOID))
		{
			PVOID* pInfo = (PVOID*)Irp->AssociatedIrp.SystemBuffer;

			*pInfo = (PVOID)MmGetPhysicalAddress(*pInfo).QuadPart;

			Info = inLen;
		}
		break;
	}
	default:
	{
		Status = STATUS_INVALID_DEVICE_REQUEST;                    // 4. 不识别的 IOCTL
		break;
	}
	}

	Irp->IoStatus.Status = Status;                            // 5. 回填结果
	Irp->IoStatus.Information = Info;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

#pragma code_seg("PAGE")
void UnloadDriver(IN PDRIVER_OBJECT drvObj)
{
	PAGED_CODE();
	PDEVICE_OBJECT devObj = drvObj->DeviceObject;
	if (devObj != NULL)
	{
		CallDestroyer(pGlobalManager);
		CallDestroyer(&GetSignletonMtrrMemoryTypeCache());
		CallDestroyer(&GetSignletonMtrrData());

		HookFunctionManager::Deinit();

		UNICODE_STRING symLinkName;
		RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VTXDriver");
		//如果你在DriverEntry里面调用IoCreateSymbolicLink的话加上这句
		//因为你在DriverEntry里面使用的常量跟着DriverEntry一起卸载了
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(devObj);
	}
	KdPrint(("VT-X driver has exited\n"));
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING)
{
	//过ObRegisterCallbacks驱动签名检测
	PVOID thisDrvSection = pDriverObject->DriverSection;
	*((PUINT32)((PUCHAR)thisDrvSection + 0x68)) |= 0x20;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		pDriverObject->MajorFunction[IRP_MJ_READ] =
		pDriverObject->MajorFunction[IRP_MJ_WRITE] = DriverIOHandler;
		
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlHandler;
	pDriverObject->DriverUnload = UnloadDriver;

	UINT32 initStep = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT fdo = NULL;
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&devName, L"\\Device\\VTXDriver");
	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VTXDriver");

	do
	{
		KdPrint(("DriverEntry(): Starting VT-X Driver\n"));

		status = IoCreateDevice(pDriverObject, sizeof(GlobalManager), &devName, FILE_DEVICE_UNKNOWN,
			0, TRUE, &fdo);
		if (!NT_SUCCESS(status))
			break;
		initStep = 1;

		status = IoCreateSymbolicLink(&symLinkName, &devName);
		if (!NT_SUCCESS(status))
			break;
		initStep = 2;

		GetSignletonMtrrData();
		GetSignletonMtrrMemoryTypeCache();

		//使用设备扩展初始化GlobalManager
		pGlobalManager = ((GlobalManager*)fdo->DeviceExtension);
		CallConstructor(pGlobalManager);

		HookFunctionManager::Init();

		//进入VM
		status = pGlobalManager->Init();
		if (!NT_SUCCESS(status))
			break;

		//暂时退出VM
		pGlobalManager->vtxManager.LeaveVirtualization();

		initStep = 3;

		fdo->Flags |= DO_BUFFERED_IO;
		KdPrint(("DriverEntry(): VT-X Driver Start successfully.\n"));
	} while (0);

	if (!NT_SUCCESS(status))
	{
		CHAR errorInfo[100] = {};
		sprintf(errorInfo, "DriverEntry(): VT-X Driver Init Err, Step: %d, Code: %x\n", initStep, status);
		KdPrint((errorInfo));
		switch (initStep)
		{
		case 3:
			CallDestroyer(pGlobalManager);
		case 2:
			IoDeleteSymbolicLink(&symLinkName);
		case 1:
			IoDeleteDevice(fdo);
		default:
			break;
		}
	}

	return status;
}

#pragma code_seg("PAGE")
void HookFunctionManager::SetSyscallIndex(char* pFunctionName, UINT32 index)
{
	KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>* pContainer = (KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer;
	for (SIZE_TYPE idx = 0; idx < pContainer->Length(); ++idx)
	{
		//如果字符串匹配
		if (!strncmp(&(*pContainer)[idx].functionName[0], pFunctionName, sizeof (*pContainer)[idx].functionName))
		{
			(*pContainer)[idx].index = index;
			return;
		}
	}

	SyscallIndexIn item = { {}, index };
	strncpy_s(item.functionName, sizeof item.functionName, pFunctionName, strlen(pFunctionName));
	pContainer->PushBack(item);
}

#pragma code_seg("PAGE")
UINT32 HookFunctionManager::GetSyscallIndex(char* pFunctionName)
{
	KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>* pContainer = (KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer;
	for (SIZE_TYPE idx = 0; idx < pContainer->Length(); ++idx)
	{
		//如果字符串匹配
		if (!strncmp(&(*pContainer)[idx].functionName[0], pFunctionName, sizeof(*pContainer)[idx].functionName))
			return (*pContainer)[idx].index;
	}

	return (UINT32)-1;
}
