#include "../SDK/ProcessCore.h"

// GetProcAddress equivalent for external Wow64 processes. Used widely for PE features.
// Returns the 32-bit address of a function in a 32-bit DLL in a process.
// If the address is not found, the base address of the module is returned.
DWORD Wow64GetProcAddress(HANDLE hProcess, const DWORD moduleBase, const char* funcName)
{
	DWORD pLoadLibraryFunction = NULL;

	// Read the PE headers into local memory and get the pointer to the export table.
	BYTE* const moduleBuffer = new BYTE[0x400];
	ReadProcessMemory(hProcess, (void*)moduleBase, moduleBuffer, 0x400, NULL);

	const IMAGE_DOS_HEADER* const pDOSHeader = (IMAGE_DOS_HEADER*)moduleBuffer;
	const IMAGE_NT_HEADERS32* const pNTHeader = (IMAGE_NT_HEADERS32*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	const IMAGE_OPTIONAL_HEADER32* const pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;

	IMAGE_EXPORT_DIRECTORY exportDir;
	ReadProcessMemory(hProcess, (void*)(moduleBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);

	DWORD* const funcAddresses = new DWORD[exportDir.NumberOfFunctions];
	ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfFunctions), funcAddresses, (sizeof(DWORD)* exportDir.NumberOfFunctions), NULL);

	// Iterate functions in the export table.
	for (unsigned int i = 0; i < exportDir.NumberOfFunctions; ++i)
	{
		DWORD stringPtr;
		ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfNames + (i * sizeof(DWORD))), &stringPtr, sizeof(DWORD), NULL);

		char functionName[64];
		ReadProcessMemory(hProcess, (void*)(moduleBase + stringPtr), functionName, 64, NULL);

		// Compare input function name with currently iterated one.
		if (strcmp(funcName, functionName) == 0)
		{
			WORD nameOrdinal;
			ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfNameOrdinals + (i * sizeof(WORD))), &nameOrdinal, sizeof(WORD), NULL);
			ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfFunctions + (sizeof(DWORD)* nameOrdinal)), &pLoadLibraryFunction, sizeof(DWORD), NULL);
			break;
		}
	}

	// Clean up used buffers.
	delete[] funcAddresses;
	delete[] moduleBuffer;

	// Return the correct virtual address, which is module base added by the function address RVA.
	return moduleBase + pLoadLibraryFunction;
}