#include <Windows.h>

// Defines permissions on a memory block. Allocation or protection functions can use this enumeration.
#define CRYPROTECTION_READONLY		0
#define CRYPROTECTION_READWRITE		1

#ifdef __cplusplus
extern "C"
{
#endif

	const BOOL __stdcall IsI386Process(HANDLE procHandle);
	const int CryCreateExternalThread(HANDLE procHandle, const SIZE_T StartAddress, void* parameter, BOOL suspended, int* pThreadId);
	const char* CryGetThreadPriority(HANDLE hThread);
	const BOOL CrySetThreadPriority(const int threadId, const int prior);
	const BOOL CrySuspendThread(HANDLE hProcess, const int ThreadID);
	const int CryResumeThread(const int ThreadID);
	const int CryTerminateThread(const int ThreadID);
	const int CryAllocateProcessMemory(HANDLE procHandle, const unsigned int MemorySize, const int protection, SIZE_T* pVirtualAddress);
	const BOOL CloseRemoteHandle(HANDLE procHandle, HANDLE handle);
	DWORD Wow64GetProcAddress(HANDLE hProcess, const DWORD moduleBase, const char* const funcName);

#ifdef __cplusplus
}
#endif