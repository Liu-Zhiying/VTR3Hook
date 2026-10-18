#include "utils.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include "raw_pdb/PDB.h"
#include "raw_pdb/PDB_RawFile.h"
#include "raw_pdb/PDB_InfoStream.h"

using System::Net::Http::HttpMethod;
using System::Net::WebRequest;
using System::Net::WebResponse;
using System::String;
using System::IO::File;
using System::IO::FileMode;
using System::IO::Stream;
using System::IO::FileStream;
using System::Exception;

#pragma warning(disable : 4996)

typedef unsigned char pdb_sig[0x10];
typedef unsigned int pdb_age;
typedef char pdb_file_name[MAX_PATH];

static const char MSF7_MAGIC[] = "Microsoft C/C++ MSF 7.00\r\n\x1a\DS\0\0\0";

static int read_block(FILE* f, uint32_t block_size, uint32_t idx, uint8_t* out)
{
	if (fseek(f, (long)idx * block_size, SEEK_SET) != 0)
		return -1;
	return fread(out, 1, block_size, f) == block_size ? 0 : -1;
}

static uint32_t rd_u32(const uint8_t* p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 解析 MSF 7.00 格式 PDB，提取 Info Stream 中的 signature */
int read_pdb_signature(const char* path,
	uint32_t* signature, uint32_t* age,
	uint8_t guid[16], uint32_t* version)
{
	FILE* f = fopen(path, "rb");
	if (!f) return -1;

	uint8_t header[64];
	if (fread(header, 1, 64, f) != 64 ||
		memcmp(header, MSF7_MAGIC, 32) != 0) {
		fclose(f);
		return -2; /* 不是 MSF 7.00 PDB */
	}

	uint32_t block_size = rd_u32(header + 32);
	uint32_t dir_size = rd_u32(header + 44);
	uint32_t block_map = rd_u32(header + 52);

	uint8_t* blk = (uint8_t*)malloc(block_size);
	if (!blk) { fclose(f); return -3; }

	/* 1. block map 块中存放目录占用的块号列表 */
	uint32_t n_dir_blocks = (dir_size + block_size - 1) / block_size;
	if (read_block(f, block_size, block_map, blk)) {
		free(blk); fclose(f); return -4;
	}
	uint32_t* dir_blocks = (uint32_t*)malloc((size_t)n_dir_blocks * 4);
	if (!dir_blocks) {
		free(blk); fclose(f); return -3;
	}
	for (uint32_t i = 0; i < n_dir_blocks; i++)
		dir_blocks[i] = rd_u32(blk + i * 4);

	/* 2. 拼接出目录数据 */
	uint8_t* directory = (uint8_t*)calloc(1, (size_t)dir_size + 1);
	if (!directory) {
		free(dir_blocks); free(blk); fclose(f); return -3;
	}
	for (uint32_t i = 0; i < n_dir_blocks; i++) {
		if (read_block(f, block_size, dir_blocks[i], blk)) {
			free(dir_blocks); free(directory); free(blk); fclose(f);
			return -4;
		}
		uint32_t off = i * block_size;
		uint32_t len = dir_size - off;
		if (len > block_size) len = block_size;
		memcpy(directory + off, blk, len);
	}
	free(dir_blocks);

	/* 3. 目录结构: num_streams | stream_sizes[] | 各流的块号 */
	uint32_t n_streams = rd_u32(directory);
	size_t pos = 4;
	uint32_t* sizes = (uint32_t*)malloc((size_t)n_streams * 4);
	if (!sizes) {
		free(directory); free(blk); fclose(f); return -3;
	}
	for (uint32_t i = 0; i < n_streams; i++) {
		sizes[i] = rd_u32(directory + pos);
		pos += 4;
	}

	/* 4. 找到流 1（PDB Info Stream）并读取头部 */
	int rc = -5;
	for (uint32_t i = 0; i < n_streams; i++) {
		uint32_t sz = sizes[i];
		uint32_t n = (sz == 0 || sz == 0xFFFFFFFF) ? 0
			: (sz + block_size - 1) / block_size;

		if (i == 1 && sz >= 28) {
			uint8_t* info = (uint8_t*)malloc(sz);
			if (!info) {
				free(sizes); free(directory); free(blk); fclose(f);
				return -3;
			}
			for (uint32_t j = 0; j < n; j++) {
				uint32_t id = rd_u32(directory + pos + j * 4);
				if (read_block(f, block_size, id, blk)) break;
				uint32_t off = j * block_size;
				uint32_t len = sz - off;
				if (len > block_size) len = block_size;
				memcpy(info + off, blk, len);
			}
			*version = rd_u32(info);
			*signature = rd_u32(info + 4);   /* <-- signature */
			*age = rd_u32(info + 8);
			memcpy(guid, info + 12, 16);
			free(info);
			rc = 0;
		}
		pos += (size_t)n * 4;
	}

	free(sizes);
	free(directory);
	free(blk);
	fclose(f);
	return rc;
}

// 打开内存映射文件
MemoryMappedFile OpenMemoryMappedFileReadonly(const std::string& filePath)
{
	MemoryMappedFile result = { nullptr, 0, INVALID_HANDLE_VALUE, nullptr };

	HANDLE fileHandle = CreateFileA(
		filePath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (fileHandle == INVALID_HANDLE_VALUE)
		return result;

	LARGE_INTEGER fileSize;
	if (!GetFileSizeEx(fileHandle, &fileSize))
	{
		CloseHandle(fileHandle);
		return result;
	}

	HANDLE mappingHandle = CreateFileMappingA(
		fileHandle,
		nullptr,
		PAGE_READONLY,
		0,
		0,
		nullptr
	);

	if (!mappingHandle)
	{
		CloseHandle(fileHandle);
		return result;
	}

	void* baseAddress = MapViewOfFile(
		mappingHandle,
		FILE_MAP_READ,
		0,
		0,
		0
	);

	if (!baseAddress)
	{
		CloseHandle(mappingHandle);
		CloseHandle(fileHandle);
		return result;
	}

	result.baseAddress = baseAddress;
	result.len = static_cast<size_t>(fileSize.QuadPart);
	result.fileHandle = fileHandle;
	result.mappingHandle = mappingHandle;

	return result;
}

// 关闭内存映射文件
void CloseMemoryMappedFile(MemoryMappedFile& file)
{
	if (file.baseAddress != NULL)
		UnmapViewOfFile(file.baseAddress);
	if (file.mappingHandle != NULL)
		CloseHandle(file.mappingHandle);
	if (file.fileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(file.fileHandle);

	file.baseAddress = nullptr;
	file.len = 0;
	file.fileHandle = INVALID_HANDLE_VALUE;
	file.mappingHandle = nullptr;
}

static bool get_pdb_info(const char* pefile, pdb_sig* sig, pdb_age* age, pdb_file_name* filename)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hMapping = NULL;

	bool ok = false;

	do
	{
		hFile = CreateFileA(pefile, FILE_READ_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
			break;

		hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

		if (hMapping == NULL)
			break;

		LPCBYTE pPe = (LPCBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

		if (pPe == NULL)
			break;

        // 获取DOS头
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPe;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			break;

        // 获取NT头
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pPe + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			break;

        // 获取调试目录信息
        if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size > 0) {
            PIMAGE_DEBUG_DIRECTORY pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)pPe + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

			SIZE_T debugDirConut = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);

			while (debugDirConut--)
			{
				// 假设使用CodeView格式的调试信息
				if (pDebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
					// 这里需要根据CodeView格式进一步解析获取PDB签名信息
					// 具体解析逻辑因CodeView格式而异，需要处理RSDS结构等

					LPCBYTE pCodeView = pPe + pDebugDir->PointerToRawData;

					if (pCodeView[0] == 'R' && pCodeView[1] == 'S' && pCodeView[2] == 'D' && pCodeView[3] == 'S')
					{
						memcpy(sig, pCodeView + 0x4, sizeof (pdb_sig));

						*age = *((pdb_age*)(pCodeView + 0x14));

						strcpy_s((char*)filename, sizeof(pdb_file_name), (const char*)pCodeView + 0x18);

						ok = true;
					}

				}
				++pDebugDir;
			}
        }
	} while (false);

	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if (hMapping != NULL)
		CloseHandle(hMapping);

	return ok;
}

static std::string get_pdb_sig_str(const pdb_sig& sig, pdb_age age)
{
	std::stringstream ss;

	ss << std::hex;

	ss << std::setfill('0');

	ss << std::uppercase;

	ss << std::setw(8);
	ss << *((unsigned int*)sig);
	ss << std::setw(4);
	ss << *((unsigned short*)(sig + 0x4));
	ss << std::setw(4);
	ss << *((unsigned short*)(sig + 0x6));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0x8));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0x9));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0xa));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0xb));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0xc));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0xd));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0xe));
	ss << std::setw(2);
	ss << (int)*((unsigned char*)(sig + 0xf));
	ss << std::setw(0);
	ss << age;

	return ss.str();
}

bool download_symbol(const char* pefile, const char* output)
{
	pdb_sig sig = {};
	pdb_age age = {};
	pdb_file_name filename = {};

	FileStream^ fileStream = nullptr;
	WebResponse^ response = nullptr;

	bool ok = false;

	do
	{
		if (!get_pdb_info(pefile, &sig, &age, &filename))
			break;

		//如果PDB文件，通过检查签名确认是否要重新下载
		if (File::Exists(gcnew String(output)))
		{
			uint32_t signature = 0;
			uint32_t age2 = 0;
			pdb_sig sig2;
			uint32_t version;
			if (read_pdb_signature(output, &signature, &age2, sig2, &version) == 0)
			{
				if (memcmp(sig, sig2, sizeof sig) == 0 && age <= age2)
				{
					ok = true;
					break;
				}
			}
		}

		try
		{
			fileStream = File::Open(gcnew String(output), FileMode::Create);
		}
		catch (Exception^)
		{
			break;
		}

		std::string pdb_sig_str = get_pdb_sig_str(sig, age);

		std::vector<std::string> urls;

		std::string url_base = "https://msdl.microsoft.com/download/symbols/";;
		std::string url_template;

		url_template += '/';
		url_template += pdb_sig_str;
		url_template += '/';

		urls.push_back(url_base + filename + url_template + filename);

		for (const std::string& url : urls)
			System::Console::WriteLine(gcnew System::String(url.c_str()));

		for (const std::string& url : urls)
		{
			try
			{
				WebRequest^ request = WebRequest::Create(gcnew String(url.c_str()));
				request->Method = gcnew String("GET");

				response = request->GetResponse();

				if (response->ContentLength == 0)
					break;

				Stream^ responseBody = response->GetResponseStream();

				responseBody->CopyTo(fileStream);

				responseBody->Close();

				ok = true;

				break;
			}
			catch (Exception^)
			{
			}
		}

	} while (false);

	if (fileStream != nullptr)
		fileStream->Close();

	if (response != nullptr)
		response->Close();

	return ok;
}
