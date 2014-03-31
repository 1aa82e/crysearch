#include "ProcessUtil.h"
#include "NativeAPI.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#include "GlobalDef.h"

// Enumerates every process currently running.
void EnumerateProcesses(Vector<Win32ProcessInformation>& outList)
{
	outList.Clear();
	
	NTSTATUS returnVal;
	ULONG dataLength = 0x10000;
	PSYSTEM_PROCESS_INFORMATION procInfo = NULL;
	
	// Query the system processes. If the call fails because of a length mismatch, recreate a bigger buffer and try again.
	do
	{
		procInfo = (PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(NULL, dataLength, MEM_COMMIT, PAGE_READWRITE);
		returnVal = NtInternalFunctions.NtQuerySystemInformation(SystemExtendedProcessInformation, procInfo, dataLength, &dataLength);
		if (returnVal == STATUS_INFO_LENGTH_MISMATCH)
		{
			// The length of the buffer was not sufficient. Expand the buffer before retrying.
			VirtualFree(procInfo, 0, MEM_RELEASE);
			dataLength *= 2;
		}
	}
	while (returnVal == STATUS_INFO_LENGTH_MISMATCH);
	
	if (returnVal == STATUS_SUCCESS)
	{
		PSYSTEM_PROCESS_INFORMATION curProc = procInfo;
		do
		{
			curProc = (PSYSTEM_PROCESS_INFORMATION)((Byte*)curProc + curProc->NextEntryOffset);
			
			// Skip the first two system processes.
			if ((int)curProc->UniqueProcessId > 4)
			{
				Win32ProcessInformation wpi;
				wpi.ProcessId = (int)curProc->UniqueProcessId;
				wpi.ExeTitle = WString(curProc->ImageName.Buffer, curProc->ImageName.Length).ToString();

				outList.Add(wpi);
			}
		}
		while (curProc->NextEntryOffset);
	}
	
	// Free heap allocated process information.
	VirtualFree(procInfo, 0, MEM_RELEASE);
}

// Retrieves all modules loaded from a process including base and size.
void EnumerateModules(HANDLE procHandle, const int processId)
{
	LoadedModulesList.Clear();
	
	// Some processes have so many modules. Better safe than sorry.
	HMODULE* modules = (HMODULE*)VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	DWORD modulesFound = 0;

#ifdef _WIN64
	EnumProcessModulesEx(procHandle, modules, 1024 * sizeof(HMODULE), &modulesFound, mMemoryScanner->IsX86Process() ? LIST_MODULES_32BIT : LIST_MODULES_64BIT);
#else
	EnumProcessModules(procHandle, modules, 1024 * sizeof(HMODULE), &modulesFound);
#endif
	
	for (unsigned int i = 0; i < modulesFound / sizeof(HMODULE); ++i)
	{
		Win32ModuleInformation curMod;
				
		char dllName[MAX_PATH];
		GetModuleFileNameEx(procHandle, modules[i], dllName, MAX_PATH);
		curMod.ModuleName = GetFileName(dllName);
		
		MODULEINFO modInfo;
		GetModuleInformation(procHandle, modules[i], &modInfo, sizeof(MODULEINFO));
		curMod.Length = modInfo.SizeOfImage;
		curMod.BaseAddress = (SIZE_T)modInfo.lpBaseOfDll;
		
		LoadedModulesList.Add(curMod);
	}

	// Free allocated memory.
	VirtualFree(modules, 0, MEM_RELEASE);
}

// Retrieves all threads loaded from a process.
void EnumerateThreads(const int processId, Vector<Win32ThreadInformation>& threads)
{
	threads.Clear();
	
	NTSTATUS returnVal;
	ULONG dataLength = 0x10000;
	PSYSTEM_PROCESS_INFORMATION procInfo = NULL;
	
	// Query the system processes. If the call fails because of a length mismatch, recreate a bigger buffer and try again.
	do
	{
		procInfo = (PSYSTEM_PROCESS_INFORMATION)VirtualAlloc(NULL, dataLength, MEM_COMMIT, PAGE_READWRITE);
		returnVal = NtInternalFunctions.NtQuerySystemInformation(SystemExtendedProcessInformation, procInfo, dataLength, &dataLength);
		if (returnVal == STATUS_INFO_LENGTH_MISMATCH)
		{
			// The length of the buffer was not sufficient. Expand the buffer before retrying.
			VirtualFree(procInfo, 0, MEM_RELEASE);
			dataLength *= 2;
		}
	}
	while (returnVal == STATUS_INFO_LENGTH_MISMATCH);
	
	if (returnVal == STATUS_SUCCESS)
	{
		PSYSTEM_PROCESS_INFORMATION curProc = procInfo;
		do
		{
			curProc = (PSYSTEM_PROCESS_INFORMATION)((Byte*)curProc + curProc->NextEntryOffset);
			
			// Iterate processes until the correct one is found.
			if ((int)curProc->UniqueProcessId == processId)
			{
				// Iterate threads of process.
				for (DWORD t = 0; t < curProc->NumberOfThreads; ++t)
				{
					PSYSTEM_EXTENDED_THREAD_INFORMATION curThread = &curProc->Threads[t];
					Win32ThreadInformation& newEntry = threads.Add();
					newEntry.ThreadIdentifier = (int)curThread->ThreadInfo.ClientId.UniqueThread;
					newEntry.StartAddress = curThread->Win32StartAddress ? (SIZE_T)curThread->Win32StartAddress : (SIZE_T)curThread->ThreadInfo.StartAddress;
					newEntry.Suspended = curThread->ThreadInfo.WaitReason == Suspended;
				}
			}
		}
		while (curProc->NextEntryOffset);
	}
	
	// Free heap allocated process information.
	VirtualFree(procInfo, 0, MEM_RELEASE);
}

// Enumerates heaps inside the target process.
// Returns true if the function succeeded or false if it did not.
bool EnumerateHeaps(Vector<Win32HeapInformation>& heapInfoList)
{
	// Get addresses of NTDLL functions necessary for the heap enumeration.
	HMODULE hNtDll = GetModuleHandle("ntdll.dll");
	RtlCreateQueryDebugBufferPrototype RtlCreateQueryDebugBuffer = (RtlCreateQueryDebugBufferPrototype)GetProcAddress(hNtDll, "RtlCreateQueryDebugBuffer");
	RtlDestroyQueryDebugBufferPrototype RtlDestroyQueryDebugBuffer = (RtlDestroyQueryDebugBufferPrototype)GetProcAddress(hNtDll, "RtlDestroyQueryDebugBuffer");
	RtlQueryProcessDebugInformationPrototype RtlQueryProcessDebugInformation = (RtlQueryProcessDebugInformationPrototype)GetProcAddress(hNtDll, "RtlQueryProcessDebugInformation");

	if (!RtlCreateQueryDebugBuffer || !RtlDestroyQueryDebugBuffer || !RtlQueryProcessDebugInformation)
	{
		return false;
	}
	
	// Create debug buffer to hold heap information.
	PRTL_DEBUG_INFORMATION db = RtlCreateQueryDebugBuffer(0, FALSE);
	if (!db)
	{
		return false;
	}
	
	// Get heap information and put it inside the debug buffer.
	NTSTATUS result = RtlQueryProcessDebugInformation(mMemoryScanner->GetProcessId(), PDI_HEAPS | PDI_HEAP_BLOCKS, db);
	if (result != STATUS_SUCCESS)
	{
		RtlDestroyQueryDebugBuffer(db);
		return false;
	}
	
	// Walk the heaps and add them to the input vector.
	for (unsigned int i = 0; i < db->Heaps->NumberOfHeaps; ++i)
	{
		PRTL_HEAP_INFORMATION curHeap = &db->Heaps->Heaps[i];
		Win32HeapInformation& heap = heapInfoList.Add();
		heap.VirtualAddress = (LONG_PTR)curHeap->BaseAddress;
		heap.BlockCount = curHeap->NumberOfEntries;
		heap.CommittedSize = (LONG)curHeap->BytesCommitted;
		heap.AllocatedSize = (LONG)curHeap->BytesAllocated;
		heap.Flags = curHeap->Flags;
	}

	// Clean up buffer and return.
	RtlDestroyQueryDebugBuffer(db);
	return true;
}