#include "driver_utils.h"
#include "utils.h"
#include "pdb_validator.h"
#include "pdb_search.h"
#include "syscall_reader.h"
#include "../StartVTXHookDriverFromNone/CtrlDefine.h"
#include "Cpu.h"
#include <stdio.h>
#include <string>
#include <locale>
#include <codecvt>
#include <Windows.h>
#include <stdlib.h>

constexpr LPCWSTR pServiceNameIntel = L"VTXDriver";
constexpr LPCSTR pDriverNameIntel = "StartVTXHookDriverFromNone.sys";
constexpr LPCWSTR pDriverDeviceNameIntel = L"\\\\.\\VTXDriver";

constexpr LPCWSTR pServiceNameAMD = L"AMDVDriver";
constexpr LPCSTR pDriverNameAMD = "AMDVTDriver.sys";
constexpr LPCWSTR pDriverDeviceNameAMD = L"\\\\.\\AMDVTDriver";

LONG continueValue = 1;

// GBK -> UTF-16 (std::wstring)
std::wstring gbk_to_utf16(const std::string& gbk)
{
	// 1. 构造一个“多字节→宽字符”的 codecvt，用系统 GBK 环境
	//    Windows: "Chinese_China.936" 或 "zh-CN"
	//    Linux:   "zh_CN.gb18030" （glibc 支持）
	std::wstring_convert<
		std::codecvt_byname<wchar_t, char, std::mbstate_t>> conv(
			new std::codecvt_byname<wchar_t, char, std::mbstate_t>(""));
	try
	{
		return conv.from_bytes(gbk);          // 真正转换
	}
	catch (const std::range_error&)
	{
		throw std::runtime_error("gbk_to_utf16: 遇到非法 GBK 字节流");
	}
}

std::string GetMainModulePath()
{
	CHAR szFileName[MAX_PATH] = {};
	DWORD length = GetModuleFileNameA(GetModuleHandle(NULL), szFileName, MAX_PATH);

	if (GetLastError() != ERROR_SUCCESS)
		return "";

	while (szFileName[length] != '\\') --length;

	szFileName[length] = 0;

	return szFileName;
}

std::string GetSystemPath()
{
	CHAR szFileName[MAX_PATH] = {};
	DWORD length = GetSystemDirectoryA(szFileName, MAX_PATH);

	if (GetLastError() != ERROR_SUCCESS)
		return "";

	while (szFileName[length] != '\\') --length;

	szFileName[length] = 0;

	return szFileName;
}
#pragma managed(push, off)
extern "C" int x1()
{
	printf("Hello,x1\n");
	printf("Hello,x1\n");
	printf("Hello,x1\n");
	return 0;
}

extern "C" int x2()
{
	printf("Hello,x2\n");
	printf("Hello,x2\n");
	printf("Hello,x2\n");
	return 0;
}
#pragma managed(pop)
int main()
{
	auto array = ReadSyscall();

	std::string modulePath = GetMainModulePath() + '\\';
	std::string pdbPath = modulePath + "ntoskrnl.pdb";

	int step = 0;

	printf("开始下载系统符号文件...\n");

	if (!download_symbol((GetSystemPath() + "\\System32\\ntoskrnl.exe").c_str(), pdbPath.c_str()))
	{
		printf("符号下载失败\n");
		return 0;
	}
	else
	{
		printf("符号下载成功!\n");
	}

	printf("符号下载完成，开始检查PDB文件完整性...\n");

	// 检查下载的PDB文件完整性
	PDBValidationInfo pdbInfo;
	PDBValidationResult result = ValidatePDBFile(pdbPath.c_str(), pdbInfo);

	if (result != PDBValidationResult::Success)
	{
		printf("PDB文件完整性检查失败: %s\n", pdbInfo.errorMessage.c_str());
		if (!pdbInfo.errorMessage.empty())
		{
			printf("错误详情: %s\n", pdbInfo.errorMessage.c_str());
		}
		printf("建议重新下载符号文件\n");
		return 0;
	}

	// 检查是否可用于调试
	if (IsPDBFileUsableForDebugging("ntoskrnl.pdb"))
	{
		printf("PDB文件可用于调试！\n");
	}
	else
	{
		printf("警告: PDB文件可能无法用于完整调试\n");
	}

	LPVOID zwCreateFileRVA = SearchRVA("ZwCreateFile", pdbPath.c_str());
	LPVOID kiServiceTableRVA = SearchRVA("KeServiceDescriptorTable", pdbPath.c_str());
	LPVOID DirectoryTableBaseRVA = SearchFieldOffset("_KPROCESS", "Pcb.DirectoryTableBase", pdbPath.c_str());

	printf("RVA of ZwCreateFile = %p\n", zwCreateFileRVA);
	printf("RVA of KeServiceDescriptorTable = %p\n", kiServiceTableRVA);
	printf("RVA of DirectoryTableBase in EPROCESS = %p\n", DirectoryTableBaseRVA);

	HANDLE hDevice = INVALID_HANDLE_VALUE;

	LPCWSTR pServiceName = NULL;
	LPCSTR pDriverName = NULL;
	LPCWSTR pDriverDeviceName = NULL;

	if (IsIntelCPU())
	{
		pServiceName = pServiceNameIntel;
		pDriverName = pDriverNameIntel;
		pDriverDeviceName = pDriverDeviceNameIntel;
	}
	else if (IsAMDCPU())
	{
		pServiceName = pServiceNameAMD;
		pDriverName = pDriverNameAMD;
		pDriverDeviceName = pDriverDeviceNameAMD;
	}
	else
	{
		printf("Unkonwn CPU!\n");
		return 0;
	}

	std::wstring driverPath = gbk_to_utf16(modulePath + pDriverName);

	do
	{
		StopNTDriverV1(pServiceName);
		RemoveNTDriverV1(pServiceName);

		if (InstallNTDriverV1(driverPath.c_str(), pServiceName))
		{
			printf("驱动安装失败！\n");
			break;
		}

		++step;

		if (StartNTDriverV1(pServiceName))
		{
			printf("驱动启动失败！\n");
			break;
		}

		++step;

		printf("驱动安装并启动成功！\n");

		hDevice = CreateFileW(pDriverDeviceName, FILE_ALL_ACCESS, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hDevice == INVALID_HANDLE_VALUE)
		{
			printf("无法打开驱动设备！，错误代码 = %u\n", GetLastError());
			break;
		}

		++step;

		KernelRvaInfo rvaInfo = {};

		rvaInfo.KeServiceDescriptorTableRVA = kiServiceTableRVA;
		rvaInfo.ZwCreateFileRVA = zwCreateFileRVA;
		rvaInfo.DirectoryTableBaseRVA = DirectoryTableBaseRVA;

		if (!DeviceIoControl(hDevice, IOCTL_SET_KERNEL_RVA, &rvaInfo, sizeof rvaInfo, NULL, 0, NULL, NULL))
		{
			printf("设置内核RVA信息失败！\n");
			break;
		}

		for (SyscallIdx& item : array)
		{
			SyscallIndexIn in = {};
			strncpy_s(in.functionName, item.functionName.c_str(), sizeof in.functionName);
			in.index = item.index;

			if (!DeviceIoControl(hDevice, IOCTL_SET_SYSCALL_INDEX, &in, sizeof in, NULL, 0, NULL, NULL))
			{
				printf("设置Syscall Index信息失败！\n");
				break;
			}
			else
			{
				printf("设置Syscall Index信息成功！   function name = %s, index = %u\n", item.functionName.c_str(), item.index);
			}
		}

		if (!DeviceIoControl(hDevice, IOCTL_START_VM_AND_HOOK, NULL, 0, NULL, 0, NULL, NULL))
		{
			printf("HOOK SSDT 失败！\n");
			break;
		}
		++step;

		printf("address of x1 = %p, address of x2 = %p\n", x1, x2);

		EptProcessHookRecordIn record = {};
		record.pOriginVirtAddr = x1;
		record.pGotoVirtAddr = x2;

		if (!DeviceIoControl(hDevice, IOCTL_ADD_HOOK, &record, sizeof record, NULL, 0, NULL, NULL))
		{
			printf("HOOK 进程内存 失败！\n");
			break;
		}

		x1();
		x1();
		x1();
		x1();
		x1();

		system("pause");

		printf("程序即将退出\n");

	} while (false);

	switch (step)
	{
	case 4:
		DeviceIoControl(hDevice, IOCTL_STOP_VM_AND_UNHOOK, NULL, 0, NULL, 0, NULL, NULL);
	case 3:
		if (hDevice != INVALID_HANDLE_VALUE)
			CloseHandle(hDevice);
	case 2:
		if (StopNTDriverV1(pServiceName))
			printf("驱动停止失败！\n");
	case 1:
		if (RemoveNTDriverV1(pServiceName))
			printf("驱动卸载失败！\n");
	default:
		break;
	}

	return 0;
}
