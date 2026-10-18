#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <Windows.h> 

// 内存映射文件结构
typedef struct _MemoryMappedFile
{
    void* baseAddress;
    size_t len;
    HANDLE fileHandle;
    HANDLE mappingHandle;
} MemoryMappedFile;

MemoryMappedFile OpenMemoryMappedFileReadonly(const std::string& filePath);
void CloseMemoryMappedFile(MemoryMappedFile& file);

bool download_symbol(const char* pefile, const char* output);

#endif
