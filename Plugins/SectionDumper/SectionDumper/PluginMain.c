#include "../../../CrySearchLibrary/SDK/Plugin.h"

CRYPLUGINHEADER SectionDumperPluginHeader;

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = (char*)dest;
	const char *s2 = (char*)src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}

const BOOL __stdcall CryGetPluginInformation(PCRYPLUGINHEADER* const pInfoBuffer)
{
	*pInfoBuffer = &SectionDumperPluginHeader;

	return TRUE;
}

const BOOL __stdcall CryInitializePlugin()
{
	SectionDumperPluginHeader.PluginType = CRYPLUGIN_DUMPER;
	SectionDumperPluginHeader.PluginName = "CrySearch Section Dumper";
	SectionDumperPluginHeader.MajorVersion = 1;
	SectionDumperPluginHeader.MinorVersion = 0;
	SectionDumperPluginHeader.Flags &= PLUGIN_DEFAULT_DUMPER;		// THIS SHOULD BE USER-DEPENDANT!!!
	SectionDumperPluginHeader.PluginState = CRYPLUGIN_STATE_LOADED;

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

		// Read headers
		ReadProcessMemory(hProcess, moduleBase, buffer, 0x400, NULL);

		pNTHeader = (IMAGE_NT_HEADERS64*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
		pOptionalHeader = (IMAGE_OPTIONAL_HEADER64*)&pNTHeader->OptionalHeader;

		// Read sections
		bufPtr = pOptionalHeader->SizeOfHeaders;

		// Iterate through sections and save them for application use.
		pSecHeader = IMAGE_FIRST_SECTION(pNTHeader);
		while (i < pNTHeader->FileHeader.NumberOfSections)
		{
			pSecHeader->Misc.VirtualSize = pSecHeader->SizeOfRawData;

			memcpy(buffer + bufPtr, pSecHeader, sizeof(IMAGE_SECTION_HEADER));
			bufPtr += sizeof(IMAGE_SECTION_HEADER);

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

	// Read headers
	ReadProcessMemory(hProcess, moduleBase, buffer, 0x400, NULL);

	pNTHeader = (IMAGE_NT_HEADERS32*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
	pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;

	// Read sections
	bufPtr = pOptionalHeader->SizeOfHeaders;

	// Iterate through sections and save them for application use.
	pSecHeader = IMAGE_FIRST_SECTION(pNTHeader);
	while (i < pNTHeader->FileHeader.NumberOfSections)
	{
		pSecHeader->Misc.VirtualSize = pSecHeader->SizeOfRawData;

		memcpy(buffer + bufPtr, pSecHeader, sizeof(IMAGE_SECTION_HEADER));
		bufPtr += sizeof(IMAGE_SECTION_HEADER);

		ReadProcessMemory(hProcess, (void*)(pOptionalHeader->ImageBase + pSecHeader->VirtualAddress), buffer + pSecHeader->PointerToRawData, pSecHeader->SizeOfRawData, NULL);

		++i;
		++pSecHeader;
	}

	return buffer;
}

const BOOL __stdcall CreateModuleDump32(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName)
{
	BOOL result = TRUE;
	DWORD bytesWritten;
	BYTE* const buffer = ReadModuleFromMemory32(hProcess, moduleBase, moduleSize);

	// Create output file
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		result = FALSE;
	}

	// Write output to dump file
	if (!WriteFile(hFile, buffer, moduleSize, &bytesWritten, NULL))
	{
		DeleteFileA(fileName);
		result = FALSE;
	}

	// All succeeded, free resources and return
	VirtualFree(buffer, 0, MEM_RELEASE);
	CloseHandle(hFile);

	return result;
}

#ifdef _WIN64
	const BOOL __stdcall CreateModuleDump64(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName)
	{
		BOOL result = TRUE;
		DWORD bytesWritten;
		BYTE* const buffer = ReadModuleFromMemory64(hProcess, moduleBase, moduleSize);

		// Create output file
		HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			result = FALSE;
		}

		// Write output to dump file
		if (!WriteFile(hFile, buffer, (DWORD)moduleSize, &bytesWritten, NULL))
		{
			DeleteFileA(fileName);
			result = FALSE;
		}

		// All succeeded, free resources and return
		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);

		return result;
	}
#endif

void __stdcall CryDestroyPlugin()
{

}