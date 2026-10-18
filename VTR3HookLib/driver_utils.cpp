#include "driver_utils.h"

UINT InstallNTDriverV1(LPCWSTR drvPath, LPCWSTR serviceName)
{
	UINT result = OPT_NO_ERROR;
	SC_HANDLE handle = NULL;
	SC_HANDLE serviceHandle = NULL;
	do
	{
		handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (handle == NULL)
		{
			result = OPEN_SCM_ERROR;
			break;
		}
		serviceHandle = CreateServiceW(handle, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, drvPath, NULL, NULL, NULL, NULL, NULL);
		if (serviceHandle == NULL)
		{
			DWORD errCode = GetLastError();
			result = CREATE_SERVICE_ERROR;
			break;
		}
	} while (0);
	if (serviceHandle != NULL)
		CloseServiceHandle(serviceHandle);
	if (handle != NULL)
		CloseServiceHandle(handle);
	return result;
}

bool IsNTDriverExistsV1(LPCWSTR serviceName, UINT& errCode)
{
	bool exist = false;
	SC_HANDLE handle = NULL;
	SC_HANDLE serviceHandle = NULL;
	do
	{
		handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (handle == NULL)
		{
			errCode = OPEN_SCM_ERROR;
			break;
		}
		serviceHandle = OpenServiceW(handle, serviceName, SERVICE_ALL_ACCESS);
		if (serviceHandle == NULL)
		{
			errCode = OPEN_SERVICE_ERROR;
			break;
		}

		exist = true;

	} while (0);
	if (serviceHandle != NULL)
		CloseServiceHandle(serviceHandle);
	if (handle != NULL)
		CloseServiceHandle(handle);
	return exist;
}

UINT RemoveNTDriverV1(LPCWSTR serviceName)
{
	UINT result = OPT_NO_ERROR;
	SC_HANDLE handle = NULL;
	SC_HANDLE serviceHandle = NULL;
	SERVICE_STATUS status = {};
	status.dwCurrentState = SERVICE_RUNNING;
	do
	{
		handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (handle == NULL)
		{
			result = OPEN_SCM_ERROR;
			break;
		}
		serviceHandle = OpenServiceW(handle, serviceName, SERVICE_ALL_ACCESS);
		if (serviceHandle == NULL)
		{
			result = OPEN_SERVICE_ERROR;
			break;
		}
		if (!DeleteService(serviceHandle))
		{
			result = REMOVE_SERVICE_ERROR;
			break;
		}
	} while (0);
	if (serviceHandle != NULL)
		CloseServiceHandle(serviceHandle);
	if (handle != NULL)
		CloseServiceHandle(handle);
	return result;
}

UINT StartNTDriverV1(LPCWSTR serviceName)
{
	UINT result = OPT_NO_ERROR;
	SC_HANDLE handle = NULL;
	SC_HANDLE serviceHandle = NULL;
	do
	{
		handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (handle == NULL)
		{
			result = OPEN_SCM_ERROR;
			break;
		}
		serviceHandle = OpenServiceW(handle, serviceName, SERVICE_ALL_ACCESS);
		if (serviceHandle == NULL)
		{
			result = OPEN_SERVICE_ERROR;
			break;
		}
		if (!StartServiceW(serviceHandle, 0, NULL))
		{
			result = START_SERVICE_ERROR;
			break;
		}
	} while (0);
	if (serviceHandle != NULL)
		CloseServiceHandle(serviceHandle);
	if (handle != NULL)
		CloseServiceHandle(handle);
	return result;
}

UINT StopNTDriverV1(LPCWSTR serviceName)
{
	UINT result = OPT_NO_ERROR;
	SC_HANDLE handle = NULL;
	SC_HANDLE serviceHandle = NULL;
	SERVICE_STATUS status = {};
	status.dwCurrentState = SERVICE_RUNNING;
	do
	{
		handle = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (handle == NULL)
		{
			result = OPEN_SCM_ERROR;
			break;
		}
		serviceHandle = OpenServiceW(handle, serviceName, SERVICE_ALL_ACCESS);
		if (serviceHandle == NULL)
		{
			result = OPEN_SERVICE_ERROR;
			break;
		}
		if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status) || status.dwCurrentState != SERVICE_STOPPED)
		{
			result = STOP_SERVICE_ERROR;
			break;
		}
	} while (0);
	if (serviceHandle != NULL)
		CloseServiceHandle(serviceHandle);
	if (handle != NULL)
		CloseServiceHandle(handle);
	return result;
}