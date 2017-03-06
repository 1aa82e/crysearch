#include "../../../CrySearchLibrary/SDK/Plugin.h"

#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

CRYPLUGINHEADER SectionDumperPluginHeader;
char creditArray[128]; //"CrySearch VirtualDump&&CrySearch dump engine that works better for .NET processes.&Written by evolution536."

// --------------------------------------------------------------------------------------------------------------------------

// Custom memcpy to avoid linking against CRT.
#pragma function(memcpy)
void* memcpy(void* dest, const void* src, size_t n)
{
	char *s1 = (char*)dest;
	const char *s2 = (char*)src;
	for (; 0 < n; --n)*s1++ = *s2++;
	return dest;
}

// evolution536 own implementation of memset, quickly written to avoid linker errors. :+)
#pragma function(memset)
void* memset(void* _Dst, int _Val, size_t _Size)
{
	BYTE* iterator = (BYTE*)_Dst;
	const BYTE* endIterator = iterator + _Val;

	while (iterator < endIterator)
	{
		*iterator++ = _Val;
	}

	return _Dst;
}

// --------------------------------------------------------------------------------------------------------------------------

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

	// Initialize plugin header with information.
	memset(&SectionDumperPluginHeader, 0, sizeof(CRYPLUGINHEADER));
	SectionDumperPluginHeader.PluginFeatures |= CRYPLUGIN_DUMPER;
	SectionDumperPluginHeader.PluginName = "CrySearch VirtualDump";
	SectionDumperPluginHeader.MajorVersion = 1;
	SectionDumperPluginHeader.MinorVersion = 0;
	SectionDumperPluginHeader.PluginState = CRYPLUGIN_STATE_LOADED;

	// Put obfuscated string values into credit array.
	*iterator++ = 0x53797243;
	*iterator++ = 0x63726165;
	*iterator++ = 0x69562068;
	*iterator++ = 0x61757472;
	*iterator++ = 0x6d75446c;
	*iterator++ = 0x43262670;
	*iterator++ = 0x65537972;
	*iterator++ = 0x68637261;
	*iterator++ = 0x6d756420;
	*iterator++ = 0x6e652070;
	*iterator++ = 0x656e6967;
	*iterator++ = 0x61687420;
	*iterator++ = 0x6f772074;
	*iterator++ = 0x20736b72;
	*iterator++ = 0x74746562;
	*iterator++ = 0x66207265;
	*iterator++ = 0x2e20726f;
	*iterator++ = 0x2054454e;
	*iterator++ = 0x636f7270;
	*iterator++ = 0x65737365;
	*iterator++ = 0x57262e73;
	*iterator++ = 0x74746972;
	*iterator++ = 0x62206e65;
	*iterator++ = 0x76652079;
	*iterator++ = 0x74756c6f;
	*iterator++ = 0x356e6f69;
	*iterator = 0x2e3633;

	return TRUE;
}

// Places a signature in the PE header of the dumped process module.
void PlaceSignatureInDump(IMAGE_DOS_HEADER* const buffer, const unsigned int maxCount)
{
	// Get pointer to the desired fields. We can place some stuff in the symbol table fields, since they are not used.
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)buffer + buffer->e_lfanew);
	if ((SIZE_T)nt < (SIZE_T)buffer + maxCount)
	{
		nt->FileHeader.NumberOfSymbols = 0x6F7665;
		nt->FileHeader.PointerToSymbolTable = 0x797243;
	}
}

const bool __stdcall CreateModuleDump32(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName)
{
	// Create output file.
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// Set the base address for VirtualQueryEx to the correct value.
	MEMORY_BASIC_INFORMATION block;
	block.BaseAddress = (void*)moduleBase;
	SIZE_T dwBlockSize = 0;

	// Create a buffer for the memory page.
	BYTE* buffer = (BYTE*)VirtualAlloc(NULL, moduleSize, MEM_COMMIT, PAGE_READWRITE);

	// Dumping the whole module failed, scan the memory information instead.
	while (VirtualQueryEx(hProcess, block.BaseAddress, &block, sizeof(block)) && (dwBlockSize < moduleSize))
	{
		// We are interested in committed pages.
		if (block.State == MEM_COMMIT)
		{
			// Check if the pages are accessible. Protected memory pages should be skipped and filled with zero's.
			if ((block.Protect & PAGE_GUARD) || (block.Protect & PAGE_NOACCESS))
			{
				memset(buffer + dwBlockSize, 0, block.RegionSize);
			}
			else
			{
				SIZE_T bytesRead;
				ReadProcessMemory(hProcess, block.BaseAddress, buffer + dwBlockSize, block.RegionSize, &bytesRead);
				if (bytesRead != block.RegionSize)
				{
					// Failed to read the memory, save it as failure.
					memset(buffer + dwBlockSize, 0, block.RegionSize);
				}
			}
		}
		else
		{
			// This is not a committed page, but it still fills the output file as padding.
			memset(buffer + dwBlockSize, 0, block.RegionSize);
		}

		// Increment output buffer size.
		dwBlockSize += block.RegionSize;

		// Increment the region address.
		block.BaseAddress = (BYTE*)block.BaseAddress + block.RegionSize;
	}

	// Place a CrySearch signature in the dumped file.
	PlaceSignatureInDump((IMAGE_DOS_HEADER*)buffer, moduleSize);

	// Flush the buffer to the output file.
	WriteFile(hFile, buffer, moduleSize, NULL, NULL);

	// Free the local buffer for the current page contents.
	VirtualFree(buffer, 0, MEM_RELEASE);

	// All succeeded, free resources and return.
	CloseHandle(hFile);

	return true;
}

#ifdef _WIN64
const bool __stdcall CreateModuleDump64(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName)
{
	// Create output file.
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// Set the base address for VirtualQueryEx to the correct value.
	MEMORY_BASIC_INFORMATION block;
	block.BaseAddress = (void*)moduleBase;
	SIZE_T dwBlockSize = 0;

	// Create a buffer for the memory page.
	BYTE* buffer = (BYTE*)VirtualAlloc(NULL, moduleSize, MEM_COMMIT, PAGE_READWRITE);

	// Dumping the whole module failed, scan the memory information instead.
	while (VirtualQueryEx(hProcess, block.BaseAddress, &block, sizeof(block)) && (dwBlockSize < moduleSize))
	{
		// We are interested in committed pages.
		if (block.State == MEM_COMMIT)
		{
			// Check if the pages are accessible. Protected memory pages should be skipped and filled with zero's.
			if ((block.Protect & PAGE_GUARD) || (block.Protect & PAGE_NOACCESS))
			{
				memset(buffer + dwBlockSize, 0, block.RegionSize);
			}
			else
			{
				SIZE_T bytesRead;
				ReadProcessMemory(hProcess, block.BaseAddress, buffer + dwBlockSize, block.RegionSize, &bytesRead);
				if (bytesRead != block.RegionSize)
				{
					// Failed to read the memory, save it as failure.
					memset(buffer + dwBlockSize, 0, block.RegionSize);
				}
			}
		}
		else
		{
			// This is not a committed page, but it still fills the output file as padding.
			memset(buffer + dwBlockSize, 0, block.RegionSize);
		}

		// Increment output buffer size.
		dwBlockSize += block.RegionSize;

		// Increment the region address.
		block.BaseAddress = (BYTE*)block.BaseAddress + block.RegionSize;
	}

	// Place a CrySearch signature in the dumped file.
	PlaceSignatureInDump((IMAGE_DOS_HEADER*)buffer, moduleSize);

	// Flush the buffer to the output file.
	WriteFile(hFile, buffer, moduleSize, NULL, NULL);

	// Free the local buffer for the current page contents.
	VirtualFree(buffer, 0, MEM_RELEASE);

	// All succeeded, free resources and return.
	CloseHandle(hFile);

	return true;
}
#endif

void __stdcall CryDestroyPlugin()
{

}