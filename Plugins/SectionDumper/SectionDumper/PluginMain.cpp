#include "../../../CrySearchLibrary/SDK/Plugin.h"

CRYPLUGINHEADER SectionDumperPluginHeader;
char creditArray[128];	//"CrySearch Section Dumper&&Default CrySearch dump engine&written by evolution536."

#define ALIGN_ADDR(addr, alignment) (addr % alignment) ? (addr + alignment - (addr % alignment)) : (addr)

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = (char*)dest;
	const char *s2 = (char*)src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}

const bool __stdcall CryGetPluginInformation(PCRYPLUGINHEADER* const pInfoBuffer)
{
	*pInfoBuffer = &SectionDumperPluginHeader;

	return TRUE;
}

void __stdcall CryGetPluginAbout(char** const pOutputString)
{
	*pOutputString = creditArray;
}

const bool __stdcall CryInitializePlugin()
{
	DWORD* iterator = (DWORD*)creditArray;

	// Initialize the plugin header with information.
	memset(&SectionDumperPluginHeader, 0, sizeof(CRYPLUGINHEADER));
	SectionDumperPluginHeader.PluginFeatures |= CRYPLUGIN_DUMPER;
	SectionDumperPluginHeader.PluginName = "CrySearch Section Dumper";
	SectionDumperPluginHeader.MajorVersion = 1;
	SectionDumperPluginHeader.MinorVersion = 0;
	SectionDumperPluginHeader.Flags |= PLUGIN_CLASS_DEFAULT;
	SectionDumperPluginHeader.PluginState = CRYPLUGIN_STATE_LOADED;

	// Fill the credit obf string array with its values.
	*iterator++ = 0x53797243;
	*iterator++ = 0x63726165;
	*iterator++ = 0x65532068;
	*iterator++ = 0x6f697463;
	*iterator++ = 0x7544206e;
	*iterator++ = 0x7265706d;
	*iterator++ = 0x65442626;
	*iterator++ = 0x6c756166;
	*iterator++ = 0x72432074;
	*iterator++ = 0x61655379;
	*iterator++ = 0x20686372;
	*iterator++ = 0x706d7564;
	*iterator++ = 0x676e6520;
	*iterator++ = 0x26656e69;
	*iterator++ = 0x74697277;
	*iterator++ = 0x206e6574;
	*iterator++ = 0x65207962;
	*iterator++ = 0x756c6f76;
	*iterator++ = 0x6e6f6974;
	*iterator++ = 0x2e363335;
	*iterator = 0x0;

	return TRUE;
}

#ifdef _WIN64
	BYTE* const ReadModuleFromMemory64(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize)
	{
		BYTE* const buffer = (BYTE*)VirtualAlloc(NULL, moduleSize, MEM_COMMIT, PAGE_READWRITE);
		const IMAGE_NT_HEADERS64* pNTHeader = NULL;
		const IMAGE_OPTIONAL_HEADER64* pOptionalHeader = NULL;
		DWORD i = 0;
		IMAGE_SECTION_HEADER* pSecHeader;
		DWORD bufPtr;

		// Read headers.
		ReadProcessMemory(hProcess, moduleBase, buffer, 0x400, NULL);

		pNTHeader = (IMAGE_NT_HEADERS64*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
		pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader;
		bufPtr = pOptionalHeader->SizeOfHeaders;

		// Iterate through sections and save them for application use.
		pSecHeader = IMAGE_FIRST_SECTION(pNTHeader);
		while (i < pNTHeader->FileHeader.NumberOfSections)
		{
			memcpy(buffer + bufPtr, pSecHeader, sizeof(IMAGE_SECTION_HEADER));
			bufPtr += sizeof(IMAGE_SECTION_HEADER);

			pSecHeader->SizeOfRawData = ALIGN_ADDR(pSecHeader->SizeOfRawData, pOptionalHeader->FileAlignment);
			ReadProcessMemory(hProcess, (void*)(pOptionalHeader->ImageBase + pSecHeader->VirtualAddress), buffer + pSecHeader->PointerToRawData, pSecHeader->SizeOfRawData, NULL);

			++i;
			++pSecHeader;
		}

		return buffer;
	}
#endif

BYTE* const ReadModuleFromMemory32(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize)
{
	BYTE* const buffer = (BYTE*)VirtualAlloc(NULL, moduleSize, MEM_COMMIT, PAGE_READWRITE);
	const IMAGE_NT_HEADERS32* pNTHeader = NULL;
	const IMAGE_OPTIONAL_HEADER32* pOptionalHeader = NULL;
	DWORD i = 0;
	IMAGE_SECTION_HEADER* pSecHeader;
	DWORD bufPtr;

	// Read headers.
	ReadProcessMemory(hProcess, moduleBase, buffer, 0x400, NULL);

	pNTHeader = (IMAGE_NT_HEADERS32*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
	pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;
	bufPtr = pOptionalHeader->SizeOfHeaders;

	// Iterate through sections and save them for application use.
	pSecHeader = IMAGE_FIRST_SECTION(pNTHeader);
	while (i < pNTHeader->FileHeader.NumberOfSections)
	{
		memcpy(buffer + bufPtr, pSecHeader, sizeof(IMAGE_SECTION_HEADER));
		bufPtr += sizeof(IMAGE_SECTION_HEADER);

		pSecHeader->SizeOfRawData = ALIGN_ADDR(pSecHeader->SizeOfRawData, pOptionalHeader->FileAlignment);
		ReadProcessMemory(hProcess, (void*)(pOptionalHeader->ImageBase + pSecHeader->VirtualAddress), buffer + pSecHeader->PointerToRawData, pSecHeader->SizeOfRawData, NULL);

		++i;
		++pSecHeader;
	}

	return buffer;
}

const bool __stdcall CreateModuleDump32(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName)
{
	bool result = true;
	DWORD bytesWritten;
	BYTE* const buffer = ReadModuleFromMemory32(hProcess, moduleBase, moduleSize);

	// Create output file
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		result = false;
	}

	// Write output to dump file
	if (!WriteFile(hFile, buffer, moduleSize, &bytesWritten, NULL))
	{
		DeleteFileA(fileName);
		result = false;
	}

	// All succeeded, free resources and return
	VirtualFree(buffer, 0, MEM_RELEASE);
	CloseHandle(hFile);

	return result;
}

#ifdef _WIN64
	const bool __stdcall CreateModuleDump64(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName)
	{
		bool result = true;
		DWORD bytesWritten;
		BYTE* const buffer = ReadModuleFromMemory64(hProcess, moduleBase, moduleSize);

		// Create output file
		HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			result = false;
		}

		// Write output to dump file
		if (!WriteFile(hFile, buffer, (DWORD)moduleSize, &bytesWritten, NULL))
		{
			DeleteFileA(fileName);
			result = false;
		}

		// All succeeded, free resources and return
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);

		return result;
	}
#endif

void __stdcall CryProcessPluginEvent(CCryPluginEvent event, void* pParameter)
{
	switch (event)
	{
		case CRYPLUGINEVENT_PROCESS_OPENED:
			break;
		case CRYPLUGINEVENT_PROCESS_CLOSED:
			break;
		case CRYPLUGINEVENT_ERROR:
			break;
	}
}

void __stdcall CryDestroyPlugin()
{

}