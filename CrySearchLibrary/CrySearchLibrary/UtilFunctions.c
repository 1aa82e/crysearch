#include "../SDK/UtilFunctions.h"

// Sets bit flags on a specified numeric value.
void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue)
{
	const DWORD_PTR mask = (1 << bits) - 1;
	*dw = (*dw & ~(mask << lowBit)) | (newValue << lowBit);
}

// Checks whether an integer value is a multiple of another value.
const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal)
{
	return (intVal % mulVal) == 0;
}

// This function is used by CrySearch to identify the architecture of the loaded process, very important and widely used, the whole application depends on it.
// Returns true if the target process is running in wow64. When this function is called from an x86 operating system, the return value is undefined.
const BOOL __stdcall IsI386Process(HANDLE procHandle)
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
	
	return is32;
}

// Creates a thread inside the loaded process using the default user-mode WINAPI function(s).
// 0 = succeeded
// -1 = failed, failed to create the remote thread
const int CryCreateExternalThread(HANDLE procHandle, const SIZE_T StartAddress, void* parameter, BOOL suspended, int* pThreadId)
{
	int result = 0;
	HANDLE hThread;
	
	// Attempt to create the thread.
	if (!(hThread = CreateRemoteThread(procHandle, NULL, 0, (LPTHREAD_START_ROUTINE)StartAddress, parameter, suspended ? CREATE_SUSPENDED : 0, (DWORD*)pThreadId)))
	{
		result = -1;
	}
	
	CloseHandle(hThread);
	return result;
}

// Gets thread priority using the default user-mode WINAPI function(s).
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

// Sets priority on a thread using the default user-mode WINAPI function(s).
// Returns TRUE if the function succeeded and FALSE otherwise.
const BOOL CrySetThreadPriority(const int threadId, const int prior)
{
	HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
	
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	return (SetThreadPriority(hThread, prior) & CloseHandle(hThread));
}

// Attempts to suspend a thread. If CrySearch is x64 and the opened process is x86, Wow64SuspendThread is used.
// Returns true if the thread was succesfully suspended and the thread handle succesfully closed. Returns false otherwise.
const BOOL CrySuspendThread(HANDLE hProcess, const int ThreadID)
{
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadID);
	
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return FALSE;
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

// Resume a thread using the default user-mode WINAPI function(s).
// -1 = failed
// 0 = succeeded
const int CryResumeThread(const int ThreadID)
{
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, ThreadID);
	
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	return ((ResumeThread(hThread) != (DWORD)-1) & CloseHandle(hThread)) ? 0 : -1;
}

// Terminates a thread using the default user-mode WINAPI function(s).
// 0 = succeeded
// -1 = failed
const int CryTerminateThread(const int ThreadID)
{
	HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, ThreadID);
	
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	return (TerminateThread(hThread, 0) & CloseHandle(hThread)) ? 0 : -1;
}

// Allocates a piece of memory inside the target process. Enter 0 or 1 as protection value. Any other value can result in undefined behavior.
// 0 = succeeded
// -1 = failed, allocation of virtual memory block failed
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
// Returns TRUE if the operation succeeded, FALSE otherwise.
const BOOL CloseRemoteHandle(HANDLE procHandle, HANDLE handle)
{
	// Duplicate the handle.
	HANDLE hDup;
	if (!DuplicateHandle(procHandle, handle, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_CLOSE_SOURCE))
	{
		return FALSE;
	}
	
	// Close the duplicated handle.
	CloseHandle(hDup);
	return TRUE;
}

#ifdef _WIN64
	// Aligns an address in memory to the specific boundary.
	__declspec(dllexport) void AlignPointer(DWORD_PTR* Address, const DWORD Boundary)
	{
		if (Boundary > 0)
		{
			if ((*Address % Boundary) > 0)
			{
				const DWORD_PTR tmp = *Address;
				*Address = (tmp + Boundary) - (tmp % Boundary);
			}
		}
	}
#endif