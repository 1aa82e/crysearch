#ifndef _CrySearch_ProcessUtil_h_
#define _CrySearch_ProcessUtil_h_

#include <Core/Core.h>

using namespace Upp;

// Represents a module that is loaded into the opened process. It is used to idenfity static addresses
// and to dump data from the process' memory.
struct Win32ModuleInformation : Moveable<Win32ModuleInformation>
{
	SIZE_T BaseAddress;
#ifdef _WIN64
	__int64 Length;
#else
	int Length;
#endif
};

// Represents a process that is running on the system. It can be enumerated and used as identifying
// information to open it inside CrySearch.
struct Win32ProcessInformation : Moveable<Win32ProcessInformation>
{
	int ProcessId;
	String ExeTitle;
	String ProcessArguments;

	// The flags are WinAPI process creation flags. This allows direct pass-through of flags into CreateProcess.
	DWORD UserInterfaceFlags;
};

// Represents a thread identifier. It is used to enumerate threads inside the opened process.
struct Win32ThreadInformation : Moveable<Win32ThreadInformation>
{
	int ThreadIdentifier;
	SIZE_T StartAddress;
	bool IsSuspended;
};

// Contains information about a heap block inside a process. Heaps are solely enumerated whenever possible.
struct Win32HeapInformation : Moveable<Win32HeapInformation>
{
	LONG_PTR VirtualAddress;
	LONG BlockCount;
	LONG CommittedSize;
	LONG AllocatedSize;
	LONG Flags;
};

// Contains information about a handle in the system. Handles can be enumerated and closed.
struct Win32HandleInformation : Moveable<Win32HandleInformation>
{
	USHORT Handle;
	String ObjectType;
	String ObjectName;
	LONG ReferenceCount;
	LONG Access;
};

void EnumerateHandles(const int processId, Vector<Win32HandleInformation>& handles);
void EnumerateThreads(const int processId, Vector<Win32ThreadInformation>& threads);
void EnumerateProcesses(Vector<Win32ProcessInformation>& outList);
bool EnumerateHeaps(Vector<Win32HeapInformation>& heapInfoList);
const bool GetSingleSymbolName(HANDLE hProcess, const SIZE_T addrOffset, char* const outSymbolName, const DWORD bufferSize);
void ConstructStackTrace(HANDLE hProcess, const DWORD machineType, const void* const contextPtr, Vector<DWORD64>& outStackTrace);

// Extern thread list definition, which is needed by the disassembly window to set hardware breakpoints.
extern Vector<Win32ThreadInformation> mThreadsList;

const bool GetInlineWindowsVersion(Tuple2<int, int>* outVersion);

#endif