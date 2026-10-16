#include "utils.h"
#include "pdb_search.h"
#include "raw_pdb/PDB.h"
#include "raw_pdb/PDB_RawFile.h"
#include "raw_pdb/PDB_InfoStream.h"
#include "raw_pdb/PDB_DBIStream.h"
#include "raw_pdb/PDB_IPIStream.h"
#include "raw_pdb/PDB_NamesStream.h"
#include "raw_pdb/PDB_ErrorCodes.h"
#include "raw_pdb/Examples/ExampleTypeTable.h"
#include <memory>

#pragma warning(disable : 4312)

namespace cv = PDB::CodeView::TPI;

// ================= 内部工具（与之前相同，未改动） =================
namespace pdbdetail
{
    struct NumLeaf { uint64_t value; const uint8_t* next; };

    inline bool ReadNumericLeaf(const uint8_t*& p, NumLeaf& out)
    {
        uint16_t leaf; memcpy(&leaf, p, 2); p += 2;
        if (leaf < 0x8000u) { out.value = leaf; out.next = p; return true; }
        switch (leaf)
        {
        case 0x8000u: { int8_t   v; memcpy(&v, p, 1); p += 1; out.value = (uint64_t)v; break; }
        case 0x8001u: { int16_t  v; memcpy(&v, p, 2); p += 2; out.value = (uint64_t)v; break; }
        case 0x8002u: { uint16_t v; memcpy(&v, p, 2); p += 2; out.value = v;           break; }
        case 0x8003u: { int32_t  v; memcpy(&v, p, 4); p += 4; out.value = (uint64_t)v; break; }
        case 0x8004u: { uint32_t v; memcpy(&v, p, 4); p += 4; out.value = v;           break; }
        case 0x8009u: { int64_t  v; memcpy(&v, p, 8); p += 8; out.value = (uint64_t)v; break; }
        case 0x800Au: { uint64_t v; memcpy(&v, p, 8); p += 8; out.value = v;           break; }
        default: return false;
        }
        out.next = p;
        return true;
    }

    inline bool Advance(const uint8_t*& p, size_t n, const uint8_t* end)
    {
        if (n > (size_t)(end - p)) return false; p += n; return true;
    }

    inline bool SkipZ(const uint8_t*& p, const uint8_t* end)
    {
        const uint8_t* q = (const uint8_t*)memchr(p, 0, (size_t)(end - p));
        if (!q) return false; p = q + 1; return true;
    }

    inline bool Align4(const uint8_t*& p, const uint8_t* base, const uint8_t* end)
    {
        size_t off = (size_t)(p - base);
        p = base + ((off + 3) & ~(size_t)3);
        return p <= end;
    }

    struct MemberInfo { bool found = false; uint64_t offset = 0; uint32_t typeIndex = 0; };

    inline void WalkFields(const TypeTable& tt, uint32_t flIdx,
        const char* name, MemberInfo& out, int depth = 0)
    {
        if (out.found || flIdx == 0 || depth > 8) return;
        const cv::Record* fl = tt.GetTypeRecord(flIdx);
        if (!fl || fl->header.kind != cv::TypeRecordKind::LF_FIELDLIST) return;

        const uint8_t* base = reinterpret_cast<const uint8_t*>(&fl->data);
        const uint8_t* p = base;
        const uint8_t* end = reinterpret_cast<const uint8_t*>(fl)
            + sizeof(cv::RecordHeader) + fl->header.size - sizeof(uint16_t);

        while (p + 2 <= end && !out.found)
        {
            uint16_t kind; memcpy(&kind, p, 2); p += 2;
            switch (kind)
            {
            case 0x150D:
            {
                if (!Advance(p, 2 + 4, end)) return;
                uint32_t t; memcpy(&t, p - 4, 4);
                NumLeaf off;
                if (!ReadNumericLeaf(p, off) || off.next > end) return;
                const char* n = reinterpret_cast<const char*>(off.next);
                const uint8_t* nz = (const uint8_t*)memchr(n, 0, (size_t)(end - (const uint8_t*)n));
                if (!nz) return;
                if (_stricmp(n, name) == 0)
                {
                    out.found = true; out.offset = off.value; out.typeIndex = t; return;
                }
                p = nz + 1;
                break;
            }
            case 0x1405:
            {
                if (!Advance(p, 2 + 4, end)) return;
                uint32_t t; memcpy(&t, p - 4, 4);
                NumLeaf off;
                if (!ReadNumericLeaf(p, off) || off.next >= end) return;
                const uint8_t* q = off.next;
                if (!Advance(q, 1, end)) return;
                const uint8_t len = q[-1];
                if (!Advance(q, len, end)) return;
                std::string nm(reinterpret_cast<const char*>(q - len), len);
                if (_stricmp(nm.c_str(), name) == 0)
                {
                    out.found = true; out.offset = off.value; out.typeIndex = t; return;
                }
                p = q;
                break;
            }
            case 0x1510: case 0x150E: case 0x150F: case 0x1512: case 0x1513:
                if (!Advance(p, 2 + 4, end)) return;
                if (!SkipZ(p, end)) return;
                break;
            case 0x1408: case 0x1406:
                if (!Advance(p, 2 + 4, end)) return;
                if (!Advance(p, 1, end)) return;
                if (!Advance(p, p[-1], end)) return;
                break;
            case 0x1502:
                if (!Advance(p, 2, end)) return;
                { NumLeaf v; if (!ReadNumericLeaf(p, v) || v.next > end) return; }
                if (!SkipZ(p, end)) return;
                break;
            case 0x1400:
                if (!Advance(p, 2 + 4, end)) return;
                { NumLeaf v; if (!ReadNumericLeaf(p, v) || v.next > end) return; }
                break;
            case 0x1401: case 0x1402:
                if (!Advance(p, 2 + 4 + 4, end)) return;
                { NumLeaf v; if (!ReadNumericLeaf(p, v) || v.next > end) return; }
                { NumLeaf v; if (!ReadNumericLeaf(p, v) || v.next > end) return; }
                break;
            case 0x1404:
            {
                if (!Advance(p, 2 + 4, end)) return;
                uint32_t sub; memcpy(&sub, p - 4, 4);
                WalkFields(tt, sub, name, out, depth + 1);
                break;
            }
            default: return;
            }
            if (!Align4(p, base, end)) return;
        }
    }

    inline const char* UdtName(const cv::Record* rec)
    {
        const uint8_t* d = reinterpret_cast<const uint8_t*>(&rec->data);
        switch (rec->header.kind)
        {
        case cv::TypeRecordKind::LF_CLASS:
        case cv::TypeRecordKind::LF_STRUCTURE:
        case cv::TypeRecordKind::LF_CLASS2:
        case cv::TypeRecordKind::LF_STRUCTURE2:
            return reinterpret_cast<const char*>(d + 18);
        case cv::TypeRecordKind::LF_UNION:
            return reinterpret_cast<const char*>(d + 10);
        case cv::TypeRecordKind::LF_ENUM:
            return reinterpret_cast<const char*>(d + 14);
        default:
            return nullptr;
        }
    }

    inline uint32_t GetUdtFieldList(const TypeTable& tt, uint32_t idx)
    {
        const cv::Record* r = tt.GetTypeRecord(idx);
        if (!r) return 0;
        if (r->header.kind == cv::TypeRecordKind::LF_FIELDLIST) return idx;
        const char* name = UdtName(r);
        if (!name) return 0;
        uint32_t field = 0;
        switch (r->header.kind)
        {
        case cv::TypeRecordKind::LF_CLASS:
        case cv::TypeRecordKind::LF_STRUCTURE:
        case cv::TypeRecordKind::LF_CLASS2:
        case cv::TypeRecordKind::LF_STRUCTURE2:
            memcpy(&field, name - 12, 4);
            break;
        case cv::TypeRecordKind::LF_UNION:
        case cv::TypeRecordKind::LF_ENUM:
            memcpy(&field, name - 4, 4);
            break;
        default: return 0;
        }
        return field;
    }
} // namespace pdbdetail

// ================= 对外封装 =================
class PdbTypes
{
public:
    PdbTypes() { m_file.fileHandle = INVALID_HANDLE_VALUE; m_file.mappingHandle = nullptr; m_file.baseAddress = nullptr; m_file.len = 0; }
    ~PdbTypes() { Close(); }

    bool Open(const char* pdbPath)
    {
        Close();

        m_file = OpenMemoryMappedFileReadonly(pdbPath);
        if (m_file.baseAddress == nullptr || m_file.len == 0)
            return false;

        if (PDB::ValidateFile(m_file.baseAddress, m_file.len) != PDB::ErrorCode::Success)
        {
            Close(); return false;
        }

        m_raw = std::make_unique<PDB::RawFile>(PDB::CreateRawFile(m_file.baseAddress));
        m_info = std::make_unique<PDB::InfoStream>(*m_raw);

        m_tpi = std::make_unique<PDB::TPIStream>(PDB::CreateTPIStream(*m_raw));
        m_tt = std::make_unique<TypeTable>(*m_tpi);
        return true;
    }

    void Close()
    {
        m_tt.reset();
        m_tpi.reset();
        m_info.reset();
        m_raw.reset();
        if (m_file.baseAddress != nullptr)
            CloseMemoryMappedFile(m_file);
    }

    bool IsOpen() const { return m_tt != nullptr; }

    bool GetFieldOffset(const char* structName, const char* fieldName,
        uint64_t& offset) const
    {
        offset = 0;
        if (!m_tt) return false;

        uint32_t udt = 0;
        if (!FindUdt(structName, udt)) return false;

        uint32_t fl = pdbdetail::GetUdtFieldList(*m_tt, udt);
        if (fl != 0)
        {
            pdbdetail::MemberInfo m;
            pdbdetail::WalkFields(*m_tt, fl, fieldName, m);
            if (m.found) { offset = m.offset; return true; }
        }
        return BruteForceField(fieldName, offset);
    }

    bool GetFieldOffsetPath(const char* structName, const char* path,
        uint64_t& offset) const
    {
        offset = 0;
        if (!m_tt) return false;

        uint32_t cur = 0;
        if (!FindUdt(structName, cur)) return false;

        std::string s(path);
        size_t pos = 0;
        while (pos <= s.size())
        {
            size_t dot = s.find('.', pos);
            std::string tok = s.substr(pos,
                dot == std::string::npos ? std::string::npos : dot - pos);

            uint32_t fl = pdbdetail::GetUdtFieldList(*m_tt, cur);
            pdbdetail::MemberInfo m;

            if (fl != 0)
                pdbdetail::WalkFields(*m_tt, fl, tok.c_str(), m);
            if (!m.found && !BruteForceMember(tok.c_str(), m))
                return false;

            offset += m.offset;
            cur = m.typeIndex;
            if (dot == std::string::npos) break;
            pos = dot + 1;
        }
        return true;
    }

    bool DumpStruct(const char* structName) const
    {
        if (!m_tt) return false;
        uint32_t udt = 0;
        if (!FindUdt(structName, udt)) return false;
        uint32_t fl = pdbdetail::GetUdtFieldList(*m_tt, udt);
        if (!fl) { printf("(no inline field list)\n"); return false; }
        DumpFields(fl);
        return true;
    }

private:
    bool FindUdt(const char* name, uint32_t& idx) const
    {
        const auto recs = m_tt->GetTypeRecords();
        for (size_t i = 0; i < recs.GetLength(); ++i)
        {
            const char* n = pdbdetail::UdtName(recs[i]);
            if (n && n[0] == '_' && _stricmp(n, name) == 0)
            {
                idx = m_tt->GetFirstTypeIndex() + (uint32_t)i;
                return true;
            }
        }
        return false;
    }

    bool BruteForceField(const char* fieldName, uint64_t& offset) const
    {
        const auto recs = m_tt->GetTypeRecords();
        int hits = 0;
        for (size_t i = 0; i < recs.GetLength(); ++i)
        {
            if (recs[i]->header.kind != cv::TypeRecordKind::LF_FIELDLIST) continue;
            pdbdetail::MemberInfo m;
            pdbdetail::WalkFields(*m_tt,
                m_tt->GetFirstTypeIndex() + (uint32_t)i, fieldName, m);
            if (m.found) { ++hits; offset = m.offset; }
        }
        return hits == 1;
    }

    bool BruteForceMember(const char* fieldName, pdbdetail::MemberInfo& out) const
    {
        const auto recs = m_tt->GetTypeRecords();
        for (size_t i = 0; i < recs.GetLength(); ++i)
        {
            if (recs[i]->header.kind != cv::TypeRecordKind::LF_FIELDLIST) continue;
            pdbdetail::MemberInfo m;
            pdbdetail::WalkFields(*m_tt,
                m_tt->GetFirstTypeIndex() + (uint32_t)i, fieldName, m);
            if (m.found) { out = m; return true; }
        }
        return false;
    }

    void DumpFields(uint32_t flIdx, int depth = 0) const
    {
        if (flIdx == 0 || depth > 8) return;
        const cv::Record* fl = m_tt->GetTypeRecord(flIdx);
        if (!fl || fl->header.kind != cv::TypeRecordKind::LF_FIELDLIST) return;

        const uint8_t* base = reinterpret_cast<const uint8_t*>(&fl->data);
        const uint8_t* p = base;
        const uint8_t* end = reinterpret_cast<const uint8_t*>(fl)
            + sizeof(cv::RecordHeader) + fl->header.size - sizeof(uint16_t);

        while (p + 2 <= end)
        {
            uint16_t kind; memcpy(&kind, p, 2); p += 2;
            switch (kind)
            {
            case 0x150D:
            {
                if (!pdbdetail::Advance(p, 2 + 4, end)) return;
                pdbdetail::NumLeaf off;
                if (!pdbdetail::ReadNumericLeaf(p, off) || off.next > end) return;
                const char* n = reinterpret_cast<const char*>(off.next);
                const uint8_t* nz = (const uint8_t*)memchr(n, 0, (size_t)(end - (const uint8_t*)n));
                if (!nz) return;
                printf("+0x%04llX  %s\n", off.value, n);
                p = nz + 1;
                break;
            }
            case 0x1405:
            {
                if (!pdbdetail::Advance(p, 2 + 4, end)) return;
                pdbdetail::NumLeaf off;
                if (!pdbdetail::ReadNumericLeaf(p, off) || off.next >= end) return;
                const uint8_t* q = off.next;
                if (!pdbdetail::Advance(q, 1, end)) return;
                const uint8_t len = q[-1];
                if (!pdbdetail::Advance(q, len, end)) return;
                printf("+0x%04llX  %.*s\n", off.value, len, q - len);
                p = q;
                break;
            }
            case 0x1502:
                if (!pdbdetail::Advance(p, 2, end)) return;
                { pdbdetail::NumLeaf v; if (!pdbdetail::ReadNumericLeaf(p, v) || v.next > end) return; }
                if (!pdbdetail::SkipZ(p, end)) return;
                break;
            case 0x1510: case 0x150E: case 0x150F: case 0x1512: case 0x1513:
                if (!pdbdetail::Advance(p, 2 + 4, end)) return;
                if (!pdbdetail::SkipZ(p, end)) return;
                break;
            case 0x1408: case 0x1406:
                if (!pdbdetail::Advance(p, 2 + 4, end)) return;
                if (!pdbdetail::Advance(p, 1, end)) return;
                if (!pdbdetail::Advance(p, p[-1], end)) return;
                break;
            case 0x1400:
                if (!pdbdetail::Advance(p, 2 + 4, end)) return;
                { pdbdetail::NumLeaf v; if (!pdbdetail::ReadNumericLeaf(p, v) || v.next > end) return; }
                break;
            case 0x1401: case 0x1402:
                if (!pdbdetail::Advance(p, 2 + 4 + 4, end)) return;
                { pdbdetail::NumLeaf v; if (!pdbdetail::ReadNumericLeaf(p, v) || v.next > end) return; }
                { pdbdetail::NumLeaf v; if (!pdbdetail::ReadNumericLeaf(p, v) || v.next > end) return; }
                break;
            case 0x1404:
            {
                if (!pdbdetail::Advance(p, 2 + 4, end)) return;
                uint32_t sub; memcpy(&sub, p - 4, 4);
                DumpFields(sub, depth + 1);
                break;
            }
            default: return;
            }
            if (!pdbdetail::Align4(p, base, end)) return;
        }
    }

    // 注意声明顺序：m_file 最先声明 => 最后析构，底层数据全程有效
    MemoryMappedFile m_file;
    std::unique_ptr<PDB::RawFile>   m_raw;
    std::unique_ptr<PDB::InfoStream> m_info;
    std::unique_ptr<PDB::TPIStream> m_tpi;
    std::unique_ptr<TypeTable>      m_tt;
};
//匹配公共符号表
PVOID SearchPublicSymbols(const PDB::ImageSectionStream& imageSectionStream, const PDB::CoalescedMSFStream& symbolRecordStream, const PDB::PublicSymbolStream& publicSymbolStream, const char* symbolName)
{
	const PDB::ArrayView<PDB::HashRecord> hashRecords = publicSymbolStream.GetRecords();
	const size_t count = hashRecords.GetLength();

	for (const PDB::HashRecord& hashRecord : hashRecords)
	{
		const PDB::CodeView::DBI::Record* record = publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
		if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32)
			continue;

		const char* name = record->data.S_PUB32.name;
		const PVOID rva = (PVOID)imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
		if (rva == 0u)
			continue;

		if (!strcmp(name, symbolName))
			return rva;
	}

	return NULL;
}

//匹配全局符号表
PVOID SearchGlobalSymbols(const PDB::ImageSectionStream& imageSectionStream, const PDB::CoalescedMSFStream& symbolRecordStream, const PDB::GlobalSymbolStream& globalSymbolStream, const char* symbolName)
{
	const PDB::ArrayView<PDB::HashRecord> hashRecords = globalSymbolStream.GetRecords();

	for (const PDB::HashRecord& hashRecord : hashRecords)
	{
		const PDB::CodeView::DBI::Record* record = globalSymbolStream.GetRecord(symbolRecordStream, hashRecord);
		const char* name = nullptr;

		PVOID rva = 0u;
		if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32)
		{
			name = record->data.S_GDATA32.name;
			rva = (PVOID)imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GDATA32.section, record->data.S_GDATA32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GTHREAD32)
		{
			name = record->data.S_GTHREAD32.name;
			rva = (PVOID)imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GTHREAD32.section, record->data.S_GTHREAD32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32)
		{
			name = record->data.S_LDATA32.name;
			rva = (PVOID)imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section, record->data.S_LDATA32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32)
		{
			name = record->data.S_LTHREAD32.name;
			rva = (PVOID)imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section, record->data.S_LTHREAD32.offset);
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT)
		{
			name = record->data.S_UDT.name;
		}
		else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT_ST)
		{
			name = record->data.S_UDT_ST.name;
		}

		if (rva == 0u)
			continue;

		if (!strcmp(name, symbolName))
			return rva;
	}

	return NULL;
}

PVOID SearchRVA(const std::string& symbolName, const std::string& dbgFileName)
{
	MemoryMappedFile file = OpenMemoryMappedFileReadonly(dbgFileName.c_str());

	if (file.baseAddress != NULL)
	{
		const PDB::RawFile pdbFile = PDB::RawFile(file.baseAddress);
		const PDB::InfoStream infoStream(pdbFile);
		const PDB::DBIStream dbiStream = PDB::CreateDBIStream(pdbFile);
		const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(pdbFile);
		const PDB::ModuleInfoStream moduleInfoStream = dbiStream.CreateModuleInfoStream(pdbFile);
		const PDB::CoalescedMSFStream symbolRecordStream = dbiStream.CreateSymbolRecordStream(pdbFile);
		const PDB::PublicSymbolStream publicSymbolStream = dbiStream.CreatePublicSymbolStream(pdbFile);
		const PDB::GlobalSymbolStream globalSymbolStream = dbiStream.CreateGlobalSymbolStream(pdbFile);

		PVOID rva = (PVOID)-1;

		do
		{
			rva = SearchPublicSymbols(imageSectionStream, symbolRecordStream, publicSymbolStream, symbolName.c_str());

			if (rva != NULL)
				break;

			rva = SearchGlobalSymbols(imageSectionStream, symbolRecordStream, globalSymbolStream, symbolName.c_str());

			if (rva != NULL)
				break;

		} while (false);

		CloseMemoryMappedFile(file);

		return rva;
	}

	return (PVOID)-1;
}

PVOID SearchFieldOffset(const std::string& structureName, const std::string& fieldName, const std::string& dbgFileName)
{
    PdbTypes types;

    types.Open(dbgFileName.c_str());

    if (!types.IsOpen())
        return (PVOID)-1;

    PVOID offset = (PVOID)-1;
    if (!types.GetFieldOffsetPath(structureName.c_str(), fieldName.c_str(), (uint64_t&)offset))
        return (PVOID)-1;
    else
        return offset;
}
