#ifndef _CrySearch_ProcessUtil_h_
#define _CrySearch_ProcessUtil_h_

#include <Core/Core.h>

using namespace Upp;

// Represents a Win32 module
struct Win32ModuleInformation : Moveable<Win32ModuleInformation>
{
	String ModuleName;
	SIZE_T BaseAddress;
#ifdef _WIN64
	__int64 Length;
#else
	int Length;
#endif
};

const Win32ModuleInformation* FindModuleInVector(const char* modName);
void GetModuleFromContainedAddress(Win32ModuleInformation** module, SIZE_T address);

// Represents a Win32 process
struct Win32ProcessInformation : Moveable<Win32ProcessInformation>
{
	int ProcessId;
	String ExeTitle;
};

// Represents a numeric thread identification value.
struct Win32ThreadInformation : Moveable<Win32ThreadInformation>
{
	int ThreadIdentifier;
	SIZE_T StartAddress;
	bool Suspended;
};

// Contains information about a heap block inside a process.
struct Win32HeapInformation : Moveable<Win32HeapInformation>
{
	LONG_PTR VirtualAddress;
	LONG BlockCount;
	LONG CommittedSize;
	LONG AllocatedSize;
	LONG Flags;
};

// Contains information about a handle in the system.
struct Win32HandleInformation : Moveable<Win32HandleInformation>
{
	USHORT Handle;
	String ObjectType;
	String ObjectName;
	LONG ReferenceCount;
	LONG Access;	
};

extern "C" const BOOL CloseRemoteHandle(HANDLE procHandle, HANDLE handle);

void EnumerateHandles(const int processId, Vector<Win32HandleInformation>& handles);
void EnumerateThreads(const int processId, Vector<Win32ThreadInformation>& threads);
void EnumerateProcesses(Vector<Win32ProcessInformation>& outList);
void EnumerateModules(HANDLE procHandle, const int processId);
bool EnumerateHeaps(Vector<Win32HeapInformation>& heapInfoList);
void ConstructStackTrace(HANDLE hProcess, const DWORD machineType, const void* const contextPtr, Vector<String>& outStackTrace);

// Defines permissions on a memory block. Allocation or protection functions can use this enumeration.
#define CRYPROTECTION_READONLY		0
#define CRYPROTECTION_READWRITE		1

extern "C" const int CryAllocateProcessMemory(HANDLE procHandle, const unsigned int MemorySize, const int protection, SIZE_T* pVirtualAddress);

// Extern thread list definition, which is needed by the disassembly window to set hardware breakpoints.
extern Vector<Win32ThreadInformation> mThreadsList;

// Thread function are simple and only use C resources so these are declared as being compiled in C files.
extern "C" const int CryResumeThread(const int ThreadID);
extern "C" const int CryTerminateThread(const int ThreadID);
extern "C" const BOOL CrySetThreadPriority(const int threadId, const int prior);

#endif