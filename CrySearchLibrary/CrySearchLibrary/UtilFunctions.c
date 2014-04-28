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