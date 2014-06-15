#include "../../../CrySearchLibrary/SDK/Plugin.h"

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

const BOOL __stdcall CryGetPluginInformation(PCRYPLUGINHEADER* const pInfoBuffer)
{
	*pInfoBuffer = &SectionDumperPluginHeader;

	return TRUE;
}

void __stdcall CryGetPluginAbout(char** const pOutputString)
{
	*pOutputString = creditArray;
}

const BOOL __stdcall CryInitializePlugin()
{
	DWORD* iterator = (DWORD*)creditArray;

	// Initialize plugin header with information.
	memset(&SectionDumperPluginHeader, 0, sizeof(CRYPLUGINHEADER));
	SectionDumperPluginHeader.PluginType |= CRYPLUGIN_DUMPER;
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

const BOOL __stdcall CreateModuleDump32(HANDLE hProcess, const void* moduleBase, const DWORD moduleSize, const char* fileName)
{
	DWORD bytesRead;
	DWORD bufferSize = moduleSize;
	BYTE* buffer = (BYTE*)VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
	MEMORY_BASIC_INFORMATION block;
	DWORD dwBlockSize = 0;
	DWORD startAddress = (DWORD)moduleBase;

	// Create output file.
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return FALSE;
	}

	// Set the base address for VirtualQueryEx to the correct value.
	block.BaseAddress = (void*)startAddress;

	// Dumping the whole module failed, scan the memory information instead.
	while (VirtualQueryEx(hProcess, block.BaseAddress, &block, sizeof(block)) && (dwBlockSize < moduleSize))
	{
		// Only dump committed pages.
		if (block.State & MEM_COMMIT)
		{
			// Check if this memory page is larger than the before-largest one. Increase the buffer size if necessary.
			if (block.RegionSize > bufferSize)
			{
				bufferSize = block.RegionSize;
				VirtualFree(buffer, 0, MEM_RELEASE);
				buffer = (BYTE*)VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
			}

			// Increment output buffer size.
			dwBlockSize += block.RegionSize;

			// Check if the page is the first page.
			if (startAddress)
			{
				block.RegionSize -= startAddress - (DWORD)block.BaseAddress;
			}

			// Check if the pages are accessible. Protected memory pages should be skipped and filled with zero's.
			if ((block.Protect & PAGE_GUARD) || (block.Protect & PAGE_NOACCESS))
			{
				memset(buffer, 0, block.RegionSize);
			}
			else
			{
				if (!ReadProcessMemory(hProcess, startAddress ? (void*)startAddress : block.BaseAddress, buffer, block.RegionSize, NULL))
				{
					// Failed to read the memory, save it as failure.
					memset(buffer, 0, block.RegionSize);
				}
			}

			// The first page indicator should be reset.
			if (startAddress)
			{
				// Reset the start address trigger variable.
				startAddress = 0;
			}

			if (*(WORD*)buffer == 0x5A4D)
				((IMAGE_NT_HEADERS32*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew))->OptionalHeader.FileAlignment = 0x1000;
			WriteFile(hFile, buffer, block.RegionSize, &bytesRead, NULL);
		}

		// Increment the region address.
		block.BaseAddress = (BYTE*)block.BaseAddress + block.RegionSize;
	}

	// It was possible to dump the entire module in one go. Write it completely to a file.
	WriteFile(hFile, buffer, bytesRead, &bytesRead, NULL);

	// All succeeded, free resources and return
	VirtualFree(buffer, 0, MEM_RELEASE);
	CloseHandle(hFile);

	return TRUE;
}

#ifdef _WIN64
const BOOL __stdcall CreateModuleDump64(HANDLE hProcess, const void* moduleBase, const ULONGLONG moduleSize, const char* fileName)
{
	return TRUE;
}
#endif

void __stdcall CryDestroyPlugin()
{

}