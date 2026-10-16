#ifndef SYSCALL_READER_H
#define SYSCALL_READER_H

#include <string>
#include <vector>

struct SyscallIdx
{
	std::string functionName;
	unsigned int index;
};

std::vector<SyscallIdx> ReadSyscall();

#endif
