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
	bool IsSuspended;
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

// Represents an entry in the call stack from a debugger breakpoint.
struct Win32StackTraceEntry : Moveable<Win32StackTraceEntry>
{
	SIZE_T Address;
	String StringRepresentation;
};

void EnumerateHandles(const int processId, Vector<Win32HandleInformation>& handles);
void EnumerateThreads(const int processId, Vector<Win32ThreadInformation>& threads);
void EnumerateProcesses(Vector<Win32ProcessInformation>& outList);
bool EnumerateHeaps(Vector<Win32HeapInformation>& heapInfoList);
void ConstructStackTrace(HANDLE hProcess, const DWORD machineType, const void* const contextPtr, Vector<Win32StackTraceEntry>& outStackTrace);

// Extern thread list definition, which is needed by the disassembly window to set hardware breakpoints.
extern Vector<Win32ThreadInformation> mThreadsList;

#endif