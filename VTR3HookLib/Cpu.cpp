#include "Cpu.h"

constexpr UINT32 GUEST_CALL_VMM_VTXCALL_FUNCTION = 0x400000ff;
constexpr UINT32 IS_IN_VTX_VTXCALL_SUBFUNCTION = 0x00000001;

void CPUString(char* outputString)
{
	UINT32 cpuid_result[4] = {};
	__cpuidex((int*)cpuid_result, 0, 0);
	memcpy(outputString, &cpuid_result[1], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32), &cpuid_result[3], sizeof(UINT32));
	memcpy(outputString + sizeof(UINT32) * 2, &cpuid_result[2], sizeof(UINT32));
	outputString[3 * sizeof(UINT32)] = 0;
}

bool IsAMDCPU()
{
	char szCpuString[13];
	CPUString(szCpuString);

	if (strcmp(szCpuString, "AuthenticAMD"))
		return false;

	return true;
}

bool IsIntelCPU()
{
	char cpuString[13] = {};
	CPUString(cpuString);

	if (strcmp(cpuString, "GenuineIntel"))
		return false;

	return true;
}

bool IntelCpuIsInVirtualization()
{
	__try
	{
		ULONG_PTR rax = GUEST_CALL_VMM_VTXCALL_FUNCTION, rbx = 0,
				  rcx = IS_IN_VTX_VTXCALL_SUBFUNCTION, rdx = 0;
		_vmcall(&rax, &rbx, &rcx, &rdx);

		if (rax == 'IN' && rbx == 'TEL' && rcx == 'VTX')
			return true;
		else
			return false;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}

bool AMDCpuIsInVirtualization()
{
	__try
	{
		ULONG_PTR rax = GUEST_CALL_VMM_VTXCALL_FUNCTION, rbx = 0,
			rcx = IS_IN_VTX_VTXCALL_SUBFUNCTION, rdx = 0;
		_vmmcall(&rax, &rbx, &rcx, &rdx);

		if (rax == 'IN' && rbx == 'AMD' && rcx == 'SVM')
			return true;
		else
			return false;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
}
