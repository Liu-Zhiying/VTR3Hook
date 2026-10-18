#ifndef PDB_SEARCH_H
#define PDB_SEARCH_H
#include <Windows.h>
#include <string>

PVOID SearchRVA(const std::string& symbolName, const std::string& dbgFileName);

PVOID SearchFieldOffset(const std::string& structureName, const std::string& fieldName, const std::string& dbgFileName);

#endif // PDB_SEARCH_H