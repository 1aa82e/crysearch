#include "CryVEHDebug.h"

// ------------------------------------------------------------------------------------------------

HANDLE hCommMapping = NULL;
CRY_VEH_COMMUNICATION_HEADER* pCommBasePtr = NULL;
PVOID hExceptionHandler = NULL;

void SetBreakpointHit(CRY_VEH_COMMUNICATION_HEADER* const header, const SIZE_T excAddress, CONTEXT* const pContext)
{
	header->BreakpointWasHit = TRUE;
	header->ExceptionAddress = excAddress;
	memcpy(&header->ThreadContext, pContext, sizeof(CONTEXT));
}

// This function is called when an exception occurs in the process where the debugger is loaded.
LONG __stdcall CryExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// Set the breakpoint data in the communication header.
	SetBreakpointHit(pCommBasePtr, (SIZE_T)ExceptionInfo->ExceptionRecord->ExceptionAddress, ExceptionInfo->ContextRecord);

	// Let the application continue execution.
	return EXCEPTION_CONTINUE_EXECUTION;
}

// Sets up the shared memory to communicate with CrySearch and sets the vectored exception handler.
BOOL __stdcall CryAttachVEHDebugger()
{
	// Create the shared memory mapping for CrySearch to open and read from.
	hCommMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, COMM_MAPPING_SIZE, L"Local\\CryVEHDebugger");

	// Check for failed communications creation.
	if (hCommMapping == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Map the shared memory to the debugger library.
	if (!(pCommBasePtr = MapViewOfFile(hCommMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, COMM_MAPPING_SIZE)))
	{
		return FALSE;
	}

	// Add vectored exception handler for the debugger to catch exceptions.
	// TRUE for a non-zero value.
	if (!(hExceptionHandler = AddVectoredExceptionHandler(TRUE, CryExceptionHandler)))
	{
		return FALSE;
	}

	// Success, return from thread.
	return TRUE;
}

// Closes communication channels and removes installed vectored exception handlers.
void __stdcall CryDetachVEHDebugger()
{
	UnmapViewOfFile(pCommBasePtr);
	CloseHandle(hCommMapping);
	RemoveVectoredExceptionHandler(hExceptionHandler);
}