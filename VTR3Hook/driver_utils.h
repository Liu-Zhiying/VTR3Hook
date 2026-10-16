#ifndef DRIVER_UTILS_H
#define DRIVER_UTILS_H

#include <Windows.h>

UINT InstallNTDriverV1(LPCWSTR drvPath, LPCWSTR serviceName);
bool IsNTDriverExistsV1(LPCWSTR serviceName, UINT& errCode);
UINT RemoveNTDriverV1(LPCWSTR serviceName);
UINT StartNTDriverV1(LPCWSTR serviceName);
UINT StopNTDriverV1(LPCWSTR serviceName);

#define OPT_NO_ERROR 0
#define OPEN_SCM_ERROR 1
#define CREATE_SERVICE_ERROR 2
#define OPEN_SERVICE_ERROR 3
#define REMOVE_SERVICE_ERROR 4
#define START_SERVICE_ERROR 5
#define STOP_SERVICE_ERROR 6

#endif