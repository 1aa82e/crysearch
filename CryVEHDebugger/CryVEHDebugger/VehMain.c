#include "CryVEHDebug.h"

HANDLE hCommMapping = NULL;
CRY_VEH_COMMUNICATION_HEADER* pCommBasePtr = NULL;
PVOID hExceptionHandler = NULL;

// This function is called when an exception occurs in the process where the debugger is loaded.
LONG __stdcall CryExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// For now...
	return EXCEPTION_CONTINUE_EXECUTION;
}

// Sets up the shared memory to communicate with CrySearch and sets the vectored exception handler.
DWORD __stdcall InitializeVehDebugger(LPVOID lpParameter)
{
	// Create the shared memory mapping for CrySearch to open and read from.
	hCommMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, COMM_MAPPING_SIZE, L"Local\\CryVEHDebugger");

	// Check for failed communications creation.
	if (hCommMapping != INVALID_HANDLE_VALUE)
	{
		return ERROR_INVALID_HANDLE;
	}

	// Map the shared memory to the debugger library.
	if (!(pCommBasePtr = MapViewOfFile(hCommMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, COMM_MAPPING_SIZE)))
	{
		return ERROR_FILE_INVALID;
	}

	// Add vectored exception handler for the debugger to catch exceptions.
	// TRUE for a non-zero value.
	if (!(hExceptionHandler = AddVectoredExceptionHandler(TRUE, CryExceptionHandler)))
	{
		return ERROR_EXCEPTION_IN_SERVICE;
	}

	// Success, return from thread.
	return ERROR_SUCCESS;
}

// Closes communication channels and removes installed vectored exception handlers.
void __stdcall FinalizeCryVEHDebugger()
{
	UnmapViewOfFile(pCommBasePtr);
	CloseHandle(hCommMapping);
	RemoveVectoredExceptionHandler(hExceptionHandler);
}

BOOL __stdcall DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			// Initialize the vectored exception handler and shared memory to communicate with CrySearch.
			CreateThread(NULL, 0, InitializeVehDebugger, NULL, 0, NULL);
			break;
		case DLL_PROCESS_DETACH:
			// Remove installed vectored exception handler and finalize shared memory.
			FinalizeCryVEHDebugger();
			break;
	}

	return TRUE;
}