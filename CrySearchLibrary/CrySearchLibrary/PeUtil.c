#include "../SDK/ProcessCore.h"

// GetProcAddress equivalent for external Wow64 processes. Used widely for PE features.
// Returns the 32-bit address of a function in a 32-bit DLL in a process.
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

	// Read the PE headers into local memory and get the pointer to the export table.
	BYTE* const moduleBuffer = (BYTE*)VirtualAlloc(NULL, 0x400, MEM_COMMIT, PAGE_READWRITE);
	ReadProcessMemory(hProcess, (void*)moduleBase, moduleBuffer, 0x400, NULL);

	// Get PE header values.
	pDOSHeader = (IMAGE_DOS_HEADER*)moduleBuffer;
	pNTHeader = (IMAGE_NT_HEADERS32*)((BYTE*)pDOSHeader + pDOSHeader->e_lfanew);
	pOptionalHeader = (IMAGE_OPTIONAL_HEADER32*)&pNTHeader->OptionalHeader;
	
	ReadProcessMemory(hProcess, (void*)(moduleBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), NULL);

	funcAddresses = (DWORD*)VirtualAlloc(NULL, exportDir.NumberOfFunctions, MEM_COMMIT, PAGE_READWRITE);
	ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfFunctions), funcAddresses, (sizeof(DWORD)* exportDir.NumberOfFunctions), NULL);

	// Iterate functions in the export table.
	while (loopIndex < exportDir.NumberOfFunctions)
	{
		DWORD stringPtr;
		char functionName[64];

		ReadProcessMemory(hProcess, (void*)(moduleBase + exportDir.AddressOfNames + (loopIndex * sizeof(DWORD))), &stringPtr, sizeof(DWORD), NULL);
		ReadProcessMemory(hProcess, (void*)(moduleBase + stringPtr), functionName, 64, NULL);

		// Compare input function name with currently iterated one.
		if (strcmp(funcName, functionName) == 0)
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