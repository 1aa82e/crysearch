#include "../SDK/ProcessCore.h"

// GetProcAddress equivalent for external Wow64 processes. Used widely for PE features. Returns the 32-bit address of a function in a 32-bit DLL in a process.
// If the address is not found, the base address of the module is returned.
const DWORD Wow64GetProcAddress(HANDLE hProcess, const DWORD moduleBase, const char* const funcName)
{
	DWORD pLoadLibraryFunction = 0;
	IMAGE_EXPORT_DIRECTORY exportDir;
	const IMAGE_DOS_HEADER* pDOSHeader = NULL;
	const IMAGE_NT_HEADERS32* pNTHeader = NULL;
	const IMAGE_OPTIONAL_HEADER32* pOptionalHeader = NULL;
	DWORD* funcAddresses = NULL;
	DWORD loopIndex = 0;
	SIZE_T bytesRead;
	BOOL b;

	// Read the PE headers into local memory and get the pointer to the export table.
	BYTE* const moduleBuffer = (BYTE*)VirtualAlloc(NULL, 0x400, MEM_COMMIT, PAGE_READWRITE);
	b = ReadProcessMemory(hProcess, (void*)moduleBase, moduleBuffer, 0x400, &bytesRead);

	// Check whether the PE headers were succesfully read.
	if (b && bytesRead == 0x400)
	{
		// Get PE header values.
		pDOSHeader = (IMAGE_DOS_HEADER*)moduleBuffer;
		pNTHeader = (IMAGE_NT_HEADERS32*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
		pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;

		// Read the export table from memory.
		b = ReadProcessMemory(hProcess, (void*)(moduleBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), &bytesRead);

		// Check if the export table was read succesfully.
		if (b && bytesRead == sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			// Read the function addresses list from memory.
			funcAddresses = (DWORD*)VirtualAlloc(NULL, (sizeof(DWORD) * exportDir.NumberOfFunctions), MEM_COMMIT, PAGE_READWRITE);
			b = ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfFunctions), funcAddresses, (sizeof(DWORD) * exportDir.NumberOfFunctions), &bytesRead);

			// Check if the list of function addresses was succesfully read.
			if (b && bytesRead == (sizeof(DWORD) * exportDir.NumberOfFunctions))
			{
				// Iterate functions in the export table.
				while (loopIndex < exportDir.NumberOfFunctions)
				{
					DWORD stringPtr;
					SIZE_T bytesRead = 0;
					char functionName[64];

					// Read the function name from the process memory.
					ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfNames + (loopIndex * sizeof(DWORD))), &stringPtr, sizeof(DWORD), NULL);
					ReadProcessMemory(hProcess, (void*)(moduleBase + stringPtr), functionName, 64, &bytesRead);

					// In case the output string was not null-terminated, do this anyway.
					functionName[min(bytesRead, sizeof(functionName) - 1)] = 0x0;

					// Compare input function name with currently iterated one.
					if (strncmp(funcName, functionName, sizeof(functionName)) == 0)
					{
						WORD nameOrdinal;
						ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfNameOrdinals + (loopIndex * sizeof(WORD))), &nameOrdinal, sizeof(WORD), NULL);
						ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfFunctions + (sizeof(DWORD)* nameOrdinal)), &pLoadLibraryFunction, sizeof(DWORD), NULL);
						break;
					}

					++loopIndex;
				}

				// Clean up used buffers.
				VirtualFree(funcAddresses, 0, MEM_RELEASE);
				VirtualFree(moduleBuffer, 0, MEM_RELEASE);

				// Return the correct virtual address, which is module base added by the function address RVA.
				return moduleBase + pLoadLibraryFunction;
			}
		}
	}

	// The function failed, return NULL.
	return NULL;
}