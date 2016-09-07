#pragma once

#include <Windows.h>

// Defines permissions on a memory block. Allocation or protection functions can use this enumeration.
#define CRYPROTECTION_READONLY		0
#define CRYPROTECTION_READWRITE		1

#ifdef __cplusplus
extern "C"
{
#endif
	
	// This function is used by CrySearch to identify the architecture of the loaded process, very important and widely used, the whole application depends on it.
	// Returns true if the target process is running in Wow64. When this function is called from an x86 operating system, the return value is undefined.
	const bool __stdcall IsI386Process(HANDLE procHandle);

	// Creates a thread inside the loaded process using the default user-mode WINAPI function(s). Returns 0 if the function succeeded and -1 if it failed.
	const int CryCreateExternalThread(HANDLE procHandle, const SIZE_T StartAddress, void* parameter, BOOL suspended, int* pThreadId);

	// Gets thread priority using the default user-mode WINAPI function GetThreadPriority. The return value is a pointer to statically allocated string.
	const char* CryGetThreadPriority(HANDLE hThread);

	// Sets priority on a thread using the default user-mode WINAPI function SetThreadPriority. Returns TRUE if the function succeeded and FALSE otherwise.
	const bool CrySetThreadPriority(const int threadId, const int prior);

	// Attempts to suspend a thread. If CrySearch is x64 and the opened process is x86, Wow64SuspendThread is used.
	// Returns TRUE if the thread was succesfully suspended and the thread handle succesfully closed. Returns FALSE otherwise.
	const bool CrySuspendThread(HANDLE hProcess, const int ThreadID);

	// Resume a thread using the default user-mode WINAPI function ResumeThread. Returns 0 if the function succeeded or -1 if it failed.
	const int CryResumeThread(const int ThreadID);

	// Terminates a thread using the default user-mode WINAPI function TerminateThread. Returns 0 if the function succeeded and -1 if it failed.
	const int CryTerminateThread(const int ThreadID);

	// Allocates a piece of memory inside the target process. Enter 0 or 1 as protection value. 0 is PAGE_EXECUTE_READ and 1 is PAGE_EXECUTE_READWRITE.
	// Any other value is not supported and the compiler assumes that these values are not supplied. Returns 0 if the function succeeded and -1 if it failed.
	const int CryAllocateProcessMemory(HANDLE procHandle, const unsigned int MemorySize, const int protection, SIZE_T* pVirtualAddress);

	// Attempts to close a remote handle. It duplicates the handle while closing the source and then closes the duplicate.
	// Returns TRUE if the operation succeeded and FALSE otherwise.
	const bool CloseRemoteHandle(HANDLE procHandle, HANDLE handle);

	// GetProcAddress equivalent for external Wow64 processes. Used widely for PE features. Returns the 32-bit address of a function in a 32-bit DLL in a process.
	// If the address is not found, the base address of the module is returned.
	const DWORD Wow64GetProcAddress(HANDLE hProcess, const DWORD moduleBase, const char* const funcName);

	// Checks whether a process is still active. It actually checks whether the process still responds to user input.
	// Returns TRUE if the process is still active and FALSE otherwise.
	const bool IsProcessActive(HANDLE procHandle);

	// Creates a snapshot of the thread specified by the threadId parameter. The thread context is put into the second parameter.
	// Returns TRUE if the snapshot succeeded and FALSE otherwise.
#ifdef _WIN64
	const bool SnapThreadContext32(const int threadId, PWOW64_CONTEXT pContext);
	const bool SnapThreadContext64(const int threadId, PCONTEXT pContext);
#else
	const bool SnapThreadContext32(const int threadId, PCONTEXT pContext);
#endif

#ifdef __cplusplus
}
#endif