#include "CryVEHDebug.h"

#define STATUS_WX86_SINGLE_STEP 			0x4000001E
#define STATUS_WX86_BREAKPOINT				0x4000001F

// ------------------------------------------------------------------------------------------------

HANDLE hCommMapping = NULL;
CRY_VEH_COMMUNICATION_HEADER* pCommBasePtr = NULL;
PVOID hExceptionHandler = NULL;

// This function is called when an exception occurs in the process where the debugger is loaded.
LONG __stdcall CryExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	CryVEHDebugger* dbgInstance = CryVEHDebugger::GetInstance();
	if (dbgInstance->IsRunning())
	{
		const SIZE_T excAddress = (SIZE_T)ExceptionInfo->ExceptionRecord->ExceptionAddress;
		if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT || 
			ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_WX86_BREAKPOINT)
		{
			if (dbgInstance->GetBreakpointCount() > 0)
			{
				const int bpIndex = dbgInstance->FindBreakpoint(excAddress);
				// Save context and insert single step!
			}
		}
		else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ||
			ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_WX86_SINGLE_STEP)
		{
			const int bpCount = dbgInstance->GetBreakpointCount();
			if (bpCount > 0)
			{
				// Find breakpoint and handle it!
			}
		}
	}

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
	if (!(pCommBasePtr = (CRY_VEH_COMMUNICATION_HEADER*)MapViewOfFile(hCommMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, COMM_MAPPING_SIZE)))
	{
		return FALSE;
	}

	// Add vectored exception handler for the debugger to catch exceptions.
	// TRUE for a non-zero value.
	if (!(hExceptionHandler = AddVectoredExceptionHandler(TRUE, CryExceptionHandler)))
	{
		return FALSE;
	}

	// Start the debugger.
	CryVEHDebugger::GetInstance()->Start();

	// Success, return from thread.
	return TRUE;
}

// Closes communication channels and removes installed vectored exception handlers.
void __stdcall CryDetachVEHDebugger()
{
	// Stop debugger.
	CryVEHDebugger::GetInstance()->Stop();

	// Free used resources.
	UnmapViewOfFile(pCommBasePtr);
	CloseHandle(hCommMapping);
	RemoveVectoredExceptionHandler(hExceptionHandler);

	// still needs to unload itself from the process!
}