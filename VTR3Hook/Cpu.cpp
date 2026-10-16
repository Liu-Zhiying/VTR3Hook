#include "Cpu.h"

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
