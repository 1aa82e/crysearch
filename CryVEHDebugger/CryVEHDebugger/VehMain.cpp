#include "CryVEHDebug.h"

#define STATUS_WX86_SINGLE_STEP 			0x4000001E
#define STATUS_WX86_BREAKPOINT				0x4000001F

// ------------------------------------------------------------------------------------------------

HINSTANCE hSelfInstance = NULL;
HANDLE hCommMapping = NULL;
CRY_VEH_COMMUNICATION_HEADER* pCommBasePtr = NULL;
PVOID hExceptionHandler = NULL;

// --------------------------------------------------------------------------------------------------------

// The debugger loop that checks for new actions in the memory mapped queue.
DWORD __stdcall DebuggerLoop(LPVOID lpParam)
{
	// Loop that runs until it is interrupted.
	CryVEHDebugger* const dbger = CryVEHDebugger::GetInstance();
	while (dbger->IsRunning())
	{
		// Can we have access to the communication structure?
		while (pCommBasePtr->CurrentlyBeingAccessed)
		{
			Sleep(5);
		}

		// Tell the communicator(s) that we are now going to read actions from the communication structure.
		pCommBasePtr->CurrentlyBeingAccessed = TRUE;

		// Walk the action queue.
		DWORD totalIterator = 0;
		for (DWORD i = 0; i < pCommBasePtr->ActionQueue.ActionCount && totalIterator < MAX_ACTION_COUNT; ++i, ++totalIterator)
		{
			// What is the current action?
			const CRY_ACTION_QUEUE_ITEM* action = &pCommBasePtr->ActionQueue.ActionData[i];
			switch (action->ActionCode)
			{
				case ACTION_SET_HARDWARE_BREAKPOINT:
					break;
				case ACTION_SET_BREAKPOINT:
					break;
				case ACTION_DISABLE_BREAKPOINT:
					break;
				case ACTION_REMOVE_BREAKPOINT:
					break;
			}
		}

		// Sleep a little before continueing the loop.
		Sleep(25);
	}

	return 0;
}

//--------------------------------------------------------------------------------------------------------

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
const bool CryAttachVEHDebugger()
{
	// Create the shared memory mapping for CrySearch to open and read from.
	hCommMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, COMM_MAPPING_SIZE, L"Local\\CryVEHDebugger");

	// Check for failed communications creation.
	if (hCommMapping == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// Map the shared memory to the debugger library.
	if (!(pCommBasePtr = (CRY_VEH_COMMUNICATION_HEADER*)MapViewOfFile(hCommMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, COMM_MAPPING_SIZE)))
	{
		return false;
	}

	// Add vectored exception handler for the debugger to catch exceptions.
	// TRUE for a non-zero value.
	if (!(hExceptionHandler = AddVectoredExceptionHandler(TRUE, CryExceptionHandler)))
	{
		return false;
	}

	// Start the debugger.
	CryVEHDebugger::GetInstance()->Start();

	// Success, return from thread.
	return true;
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
}

// VEH debugger DLL entrypoint.
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpParameter)
{
	// Save the HINSTANCE value.
	hSelfInstance = hinstDLL;

	// With what reason is DllMain executed?
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			// Initialize the debugger.
			return CryAttachVEHDebugger();
		case DLL_PROCESS_DETACH:
			// Release all used resources such that the DLL can be freed.
			CryDetachVEHDebugger();
			return TRUE;
	}
}