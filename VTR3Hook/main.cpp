#include <stdio.h>
#include <vtr3hooklib.h>
#include <stdlib.h>

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

void (NTAPI* pNtClose)(HANDLE handle);

void MyCloseHandle(HANDLE handle)
{
	printf("MyCloseHandle called!\n");
	pNtClose(handle);
}

#pragma managed(pop)
int main(int argc, char** args)
{
	pNtClose = (decltype(pNtClose))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");

	if (argc == 2 && !strcmp(args[1], "--no_init_driver"))
	{
		printf("--no_init_driver\n");

		x1();
		x1();
		x1();
		x1();

		CloseHandle(NULL);
		CloseHandle(NULL);
		CloseHandle(NULL);
		CloseHandle(NULL);

		CloseHandle(NULL);
		CloseHandle(NULL);
		CloseHandle(NULL);
		CloseHandle(NULL);

		return 0;
	}

	if (InitHookDriver())
	{
		StartVMAndHook();
		HookFunction(x1, x2);
		HookFunction(GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CloseHandle"), MyCloseHandle);

		x1();
		x1();
		x1();
		x1();

		//HOOK 系统函数，测试写时复制页的HOOK

		CloseHandle(NULL);
		CloseHandle(NULL);
		CloseHandle(NULL);
		CloseHandle(NULL);

		STARTUPINFOA si = { sizeof(si) };
		si.dwFlags = STARTF_USESTDHANDLES;  // 关键标志
		si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
		char cmdLine[] = "VTR3Hook --no_init_driver";

		PROCESS_INFORMATION info = {};

		if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &info))
		{
			printf("进程创建成功！\n");

			HookFunction(x1, x2, info.dwProcessId);
			HookFunction(GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "CloseHandle"), MyCloseHandle, info.dwProcessId);

			ResumeThread(info.hThread);

			WaitForSingleObject(info.hProcess, INFINITE);

			CloseHandle(info.hProcess);
			CloseHandle(info.hThread);
		}

		system("pause");

		DeinitHookDriver();
	}

	return 0;
}
