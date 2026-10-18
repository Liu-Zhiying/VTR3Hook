#ifndef PDB_VALIDATOR_H
#define PDB_VALIDATOR_H

#include <Windows.h>
#include <string>
#include <vector>

// PDB完整性检查结果
enum class PDBValidationResult
{
    Success = 0,
    FileNotFound,
    FileReadError,
    InvalidPDBFormat,
    InvalidSuperBlock,
    InvalidFreeBlockMap,
    InvalidStreams,
    MissingRequiredStreams,
    CorruptedData,
    UnsupportedVersion
};

// PDB完整性检查详细信息
struct PDBValidationInfo
{
    PDBValidationResult result;
    std::string errorMessage;
    size_t fileSize;
    bool hasInfoStream;
    bool hasDBIStream;
    bool hasTPIStream;
    bool hasIPIStream;
    bool hasNamesStream;
    std::vector<std::string> missingStreams;
    std::vector<std::string> corruptedStreams;
};

// 主要检查函数
PDBValidationResult ValidatePDBFile(const std::string& pdbPath, PDBValidationInfo& info);

// 详细检查函数
bool CheckPDBFileIntegrity(const std::string& pdbPath, PDBValidationInfo& info);

// 检查PDB文件是否可用于调试
bool IsPDBFileUsableForDebugging(const std::string& pdbPath);

#endif // PDB_VALIDATOR_H
