#include "utils.h"
#include "pdb_validator.h"
#include "raw_pdb/PDB.h"
#include "raw_pdb/PDB_RawFile.h"
#include "raw_pdb/PDB_InfoStream.h"
#include "raw_pdb/PDB_DBIStream.h"
#include "raw_pdb/PDB_TPIStream.h"
#include "raw_pdb/PDB_IPIStream.h"
#include "raw_pdb/PDB_NamesStream.h"
#include "raw_pdb/PDB_ErrorCodes.h"
#include <fstream>
#include <iostream>
#include <sstream>

// 主要验证函数
PDBValidationResult ValidatePDBFile(const std::string& pdbPath, PDBValidationInfo& info)
{
    // 初始化信息结构
    info = {};
    info.result = PDBValidationResult::Success;
    
    // 检查文件是否存在
    DWORD fileAttributes = GetFileAttributesA(pdbPath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES)
    {
        info.result = PDBValidationResult::FileNotFound;
        info.errorMessage = "文件不存在: " + pdbPath;
        return info.result;
    }
    
    // 获取文件大小
    HANDLE fileHandle = CreateFileA(pdbPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        info.result = PDBValidationResult::FileReadError;
        info.errorMessage = "无法打开文件进行读取";
        return info.result;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(fileHandle, &fileSize))
    {
        CloseHandle(fileHandle);
        info.result = PDBValidationResult::FileReadError;
        info.errorMessage = "无法获取文件大小";
        return info.result;
    }
    
    info.fileSize = static_cast<size_t>(fileSize.QuadPart);
    CloseHandle(fileHandle);
    
    // 打开内存映射文件
    MemoryMappedFile mappedFile = OpenMemoryMappedFileReadonly(pdbPath);
    if (!mappedFile.baseAddress)
    {
        info.result = PDBValidationResult::FileReadError;
        info.errorMessage = "无法内存映射文件";
        return info.result;
    }
    
    // 验证PDB文件基本格式
    PDB::ErrorCode validationError = PDB::ValidateFile(mappedFile.baseAddress, mappedFile.len);
    if (validationError != PDB::ErrorCode::Success)
    {
        switch (validationError)
        {
        case PDB::ErrorCode::InvalidDataSize:
        {
            info.result = PDBValidationResult::InvalidPDBFormat;
            info.errorMessage = (const std::string)"PDB文件大小无效";
            break;
        }
        case PDB::ErrorCode::InvalidSuperBlock:
        {
            info.result = PDBValidationResult::InvalidSuperBlock;
            info.errorMessage = (const std::string)"PDB超级块无效";
            break;
        }
        case PDB::ErrorCode::InvalidFreeBlockMap:
        {
            info.result = PDBValidationResult::InvalidFreeBlockMap;
            info.errorMessage = (const std::string)"PDB空闲块映射无效";
            break;
        }
        default:
        {
            info.result = PDBValidationResult::InvalidPDBFormat;
            info.errorMessage = (const std::string)"PDB文件格式无效";
            break;
        }
        }
        
        CloseMemoryMappedFile(mappedFile);
        return info.result;
    }
    
    return info.result;
}

// 详细完整性检查
bool CheckPDBFileIntegrity(const std::string& pdbPath, PDBValidationInfo& info)
{
    PDBValidationResult result = ValidatePDBFile(pdbPath, info);
    return result == PDBValidationResult::Success;
}

// 检查PDB文件是否可用于调试
bool IsPDBFileUsableForDebugging(const std::string& pdbPath)
{
    PDBValidationInfo info;
    PDBValidationResult result = ValidatePDBFile(pdbPath, info);
    
    // 检查基本要求
    if (result != PDBValidationResult::Success)
        return false;
    
    // 检查必需的流
    if (!info.hasInfoStream || !info.hasDBIStream || !info.hasTPIStream)
        return false;
    
    // 检查是否有损坏的流
    if (!info.corruptedStreams.empty())
        return false;
    
    return true;
}
