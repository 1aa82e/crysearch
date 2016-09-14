#include "../SDK/ProcessCore.h"
#include <Shlwapi.h>
#include <Psapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")

// This function is used by CrySearch to identify the architecture of the loaded process, very important and widely used, the whole application depends on it.
// Returns true if the target process is running in Wow64. When this function is called from an x86 operating system, the return value is undefined.
const bool __stdcall IsI386Process(HANDLE procHandle)
{
	SYSTEM_INFO sysInfo;
	BOOL is32;

	// Get native system info. GetSystemInfo will not return the desired information at all times.
	GetNativeSystemInfo(&sysInfo);

	if (sysInfo.wProcessorArchitecture == 0)
	{
		is32 = TRUE;
	}
	else
	{
		// 64-bit OS is detected as host, find out whether the process is running x64 or wow64.
		IsWow64Process(procHandle, &is32);
	}

	return !!is32;
}

// Creates a thread inside the loaded process using the default user-mode WINAPI function(s). Returns 0 if the function succeeded and -1 if it failed.
const int CryCreateExternalThread(HANDLE procHandle, const SIZE_T StartAddress, void* parameter, BOOL suspended, int* pThreadId)
{
	HANDLE hThread;

	// Attempt to create the thread.
	if (!(hThread = CreateRemoteThread(procHandle, NULL, 0, (LPTHREAD_START_ROUTINE)StartAddress, parameter, suspended ? CREATE_SUSPENDED : 0, (DWORD*)pThreadId)))
	{
		return -1;
	}
	else
	{
		// The function succeeded, but we don't need the handle anymore.
		CloseHandle(hThread);
		return 0;
	}
}

// Gets thread priority using the default user-mode WINAPI function GetThreadPriority. The return value is a pointer to statically allocated string.
const char* CryGetThreadPriority(HANDLE hThread)
{
	switch (GetThreadPriority(hThread))
	{
	case THREAD_PRIORITY_ABOVE_NORMAL:
		return "Above Normal";
	case THREAD_PRIORITY_BELOW_NORMAL:
		return "Below Normal";
	case THREAD_PRIORITY_HIGHEST:
		return "Highest";
	case THREAD_PRIORITY_IDLE:
		return "Idle";
	case THREAD_PRIORITY_LOWEST:
		return "Lowest";
	case THREAD_PRIORITY_NORMAL:
		return "Normal";
	case THREAD_PRIORITY_TIME_CRITICAL:
		return "Realtime";
	default:
		return "<unknown>";
	}
}

// Sets priority on a thread using the default user-mode WINAPI function SetThreadPriority. Returns TRUE if the function succeeded and FALSE otherwise.
const bool CrySetThreadPriority(const int threadId, const int prior)
{
	HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);

	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	return !!(SetThreadPriority(hThread, prior) & CloseHandle(hThread));
}

// Attempts to suspend a thread. If CrySearch is x64 and the opened process is x86, Wow64SuspendThread is used.
// Returns TRUE if the thread was succesfully suspended and the thread handle succesfully closed. Returns FALSE otherwise.
const bool CrySuspendThread(HANDLE hProcess, const int ThreadID)
{
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadID);

	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return false;
	}

#ifdef _WIN64
	if (IsI386Process(hProcess))
	{
		return ((Wow64SuspendThread(hThread) != (DWORD)-1) & CloseHandle(hThread));
	}
	else
	{
		return ((SuspendThread(hThread) != (DWORD)-1) & CloseHandle(hThread));
	}
#else
	return ((SuspendThread(hThread) != (DWORD)-1) & CloseHandle(hThread));
#endif
}

// Resume a thread using the default user-mode WINAPI function ResumeThread. Returns 0 if the function succeeded or -1 if it failed.
const int CryResumeThread(const int ThreadID)
{
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadID);

	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	return ((ResumeThread(hThread) != (DWORD)-1) & CloseHandle(hThread)) ? 0 : -1;
}

// Terminates a thread using the default user-mode WINAPI function TerminateThread. Returns 0 if the function succeeded and -1 if it failed.
const int CryTerminateThread(const int ThreadID)
{
	HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, ThreadID);

	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	return (TerminateThread(hThread, 0) & CloseHandle(hThread)) ? 0 : -1;
}

// Allocates a piece of memory inside the target process. Enter 0 or 1 as protection value. 0 is PAGE_EXECUTE_READ and 1 is PAGE_EXECUTE_READWRITE.
// Any other value is not supported and the compiler assumes that these values are not supplied. Returns 0 if the function succeeded and -1 if it failed.
const int CryAllocateProcessMemory(HANDLE procHandle, const unsigned int MemorySize, const int protection, SIZE_T* pVirtualAddress)
{
	DWORD protect;

	// Assign correct protection constants to memory block.
	switch (protection)
	{
	case 0:
		protect = PAGE_EXECUTE_READ;
		break;
	case 1:
		protect = PAGE_EXECUTE_READWRITE;
		break;
	default:
		__assume(0);
	}

	return (*pVirtualAddress = (SIZE_T)VirtualAllocEx(procHandle, NULL, MemorySize, MEM_COMMIT, protect)) ? 0 : -1;
}

// Attempts to close a remote handle. It duplicates the handle while closing the source and then closes the duplicate.
// Returns TRUE if the operation succeeded and FALSE otherwise.
const bool CloseRemoteHandle(HANDLE procHandle, HANDLE handle)
{
	// Duplicate the handle.
	HANDLE hDup;
	if (!DuplicateHandle(procHandle, handle, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_CLOSE_SOURCE))
	{
		return false;
	}

	// Close the duplicated handle.
	CloseHandle(hDup);
	return true;
}

// Checks whether a process is still active. It actually checks whether the process still responds to user input.
// Returns TRUE if the process is still active and FALSE otherwise.
const bool IsProcessActive(HANDLE procHandle)
{
	DWORD exitCode;
	GetExitCodeProcess(procHandle, &exitCode);
	return exitCode == STILL_ACTIVE;
}

// Creates a snapshot of the thread specified by the threadId parameter. The thread context is put into the second parameter.
// Returns TRUE if the snapshot succeeded and FALSE otherwise.
#ifdef _WIN64
	const bool SnapThreadContext32(const int threadId, PWOW64_CONTEXT pContext)
#else
	const bool SnapThreadContext32(const int threadId, PCONTEXT pContext)
#endif
	{
		HANDLE hThread = NULL;

		// Check input pointer validity.
		if (!pContext)
		{
			return false;
		}

		// Open handle to specified thread.
		hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, threadId);

		// Check validity of handle.
		if (!hThread || hThread == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		// Try to suspend specified thread.
#ifdef _WIN64
		if (Wow64SuspendThread(hThread) == (DWORD)-1)
#else
		if (SuspendThread(hThread) == (DWORD)-1)
#endif
		{
			CloseHandle(hThread);
			return false;
		}

		// Get architecture specific context from thread.
#ifdef _WIN64
		memset(pContext, 0, sizeof(WOW64_CONTEXT));
		pContext->ContextFlags = WOW64_CONTEXT_FULL;
		Wow64GetThreadContext(hThread, pContext);
#else
		memset(pContext, 0, sizeof(CONTEXT));
		pContext->ContextFlags = CONTEXT_FULL;
		GetThreadContext(hThread, pContext);
#endif

		// Resume thread and return.
		ResumeThread(hThread);
		CloseHandle(hThread);

		return true;
	}

#ifdef _WIN64
	// Creates a snapshot of the thread specified by the threadId parameter. The thread context is put into the second parameter.
	// Returns TRUE if the snapshot succeeded and FALSE otherwise of if the pContext pointer is NULL.
	const bool SnapThreadContext64(const int threadId, PCONTEXT pContext)
	{
		HANDLE hThread = NULL;

		// Check input pointer validity.
		if (!pContext)
		{
			return false;
		}

		// Open handle to specified thread.
		hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, threadId);

		// Check validity of handle.
		if (!hThread || hThread == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		// Try to suspend specified thread.
		if (SuspendThread(hThread) == (DWORD)-1)
		{
			CloseHandle(hThread);
			return false;
		}

		// Get context from thread.
		memset(pContext, 0, sizeof(CONTEXT));
		pContext->ContextFlags = CONTEXT_FULL;
		GetThreadContext(hThread, pContext);

		// Resume thread and return.
		ResumeThread(hThread);
		CloseHandle(hThread);

		return true;
	}
#endif