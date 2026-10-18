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
#pragma managed(pop)
int main()
{
	if (InitHookDriver())
	{
		StartVMAndHook();
		HookFunction(x1, x2);

		x1();
		x1();
		x1();
		x1();

		system("pause");

		DeinitHookDriver();
	}

	return 0;
}
