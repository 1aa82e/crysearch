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

// Retrieves the foreign name of an object based on the type.
// Returns its name if the function succeeded. Otherwise the return value is an empty string.
String GetObjectNameByType(HANDLE hObject, const wchar* pType, const DWORD length)
{
	String retVal;
	
	if (wcsncmp(pType, L"Process", length) == 0)
	{
		// The object is a process, get its filename.
		char path[MAX_PATH];
		if (GetProcessImageFileName(hObject, path, MAX_PATH))
		{
			retVal = Format("(%i) - %s", (int)GetProcessId(hObject), GetFileName(path));
		}
		else
		{
			// The process handle may have insufficient access.
			retVal = "!";
		}
	}
	else if (wcsncmp(pType, L"Thread", length) == 0)
	{
		// The object is a thread, get its thread ID.
		THREAD_BASIC_INFORMATION ti;
		if (NtInternalFunctions.NtQueryInformationThread(hObject, ThreadBasicInformation, &ti, sizeof(THREAD_BASIC_INFORMATION), NULL) == STATUS_SUCCESS)
		{
			retVal = Format("Thread ID: %i", (int)ti.ClientId.UniqueThread);
		}
		else
		{
			// Failed to query thread information.
			retVal = "!";
		}
	}
	else
	{
		// The object was not a user-friendly object that can be queried with logical information. Call NtQueryObject.
		// Allocate a buffer to hold the object name and query it into the buffer.
		POBJECT_NAME_INFORMATION objNameInfo = (POBJECT_NAME_INFORMATION)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
		if (NtInternalFunctions.NtQueryObject(hObject, ObjectNameInformation, objNameInfo, 0x1000, NULL) == STATUS_SUCCESS)
		{
			// Not all handles have a name. Sanity check for the name.
			if (objNameInfo->ObjectName.Buffer)
			{
				retVal = WString(objNameInfo->ObjectName.Buffer, objNameInfo->ObjectName.Length + 1).ToString();
			}
		}
		
		// Free the buffer allocated to hold the name.
		VirtualFree(objNameInfo, 0, MEM_RELEASE);
	}
	
	return retVal;
}

// Enumerates the heaps inside the target process. This function does not return a value.
// When it succeeds, the out Vector parameter contains the handles. If failed, the Vector is empty.
void EnumerateHandles(const int processId, Vector<Win32HandleInformation>& handles)
{
	// Clear the output Vector.
	handles.Clear();
	
	NTSTATUS returnVal;
	ULONG dataLength = 0x10000;
	PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
	
	// Query the system handles. If the call fails because of a length mismatch, recreate a bigger buffer and try again.
	do
	{
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, dataLength, MEM_COMMIT, PAGE_READWRITE);
		returnVal = NtInternalFunctions.NtQuerySystemInformation(SystemHandleInformation, handleInfo, dataLength, &dataLength);
		if (returnVal == STATUS_INFO_LENGTH_MISMATCH)
		{
			// The length of the buffer was not sufficient. Expand the buffer before retrying.
			VirtualFree(handleInfo, 0, MEM_RELEASE);
			dataLength *= 2;
		}
	}
	while (returnVal == STATUS_INFO_LENGTH_MISMATCH);
	
	if (returnVal == STATUS_SUCCESS)
	{
		// The system query succeeded, let's allocate buffers to hold the necessary information.
		POBJECT_TYPE_INFORMATION objInfo = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
		POBJECT_BASIC_INFORMATION objBasicInfo = (POBJECT_BASIC_INFORMATION)VirtualAlloc(NULL, sizeof(OBJECT_BASIC_INFORMATION), MEM_COMMIT, PAGE_READWRITE);
		
		// The count is available, let's resize the Vector to save us the additional allocations.
		handles.Reserve(handleInfo->NumberOfHandles);
		
		for (DWORD i = 0; i < handleInfo->NumberOfHandles; ++i)
		{
			const PSYSTEM_HANDLE_TABLE_ENTRY_INFO curHandle = &handleInfo->Handles[i];
			if (curHandle->UniqueProcessId == processId)
			{
				// Duplicate the handle in order to find out what object it is associated with.
				HANDLE hDup;
				DuplicateHandle(mMemoryScanner->GetHandle(), (HANDLE)curHandle->HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
				
				// Check if the handle was succesfully duplicated. StdHandle's cannot be duplicated for instance.
				if (GetLastError() != ERROR_NOT_SUPPORTED)
				{
					// Query the object to find out what kind of object it is.
					if (NtInternalFunctions.NtQueryObject(hDup, ObjectTypeInformation, objInfo, 0x1000, NULL) == STATUS_SUCCESS)
					{
						// Query the object again for its name.
						String objName = GetObjectNameByType(hDup, objInfo->TypeName.Buffer, objInfo->TypeName.Length + 1);
						if (!objName.IsEmpty())
						{
							Win32HandleInformation& newHandle = handles.Add();							
							newHandle.Handle = curHandle->HandleValue;
							newHandle.Access = curHandle->GrantedAccess;
							newHandle.ObjectType = WString(objInfo->TypeName.Buffer, objInfo->TypeName.Length).ToString();
							newHandle.ObjectName = objName;

							// Query the object again for the other information block.
							if (NtInternalFunctions.NtQueryObject(hDup, ObjectBasicInformation, objBasicInfo, sizeof(OBJECT_BASIC_INFORMATION), &dataLength) == STATUS_SUCCESS)
							{
								// As documented in ProcessHacker, we should decrement the handle count because NtQueryObject opened a handle
								// to this object too. This handle is not applicable for counting with the references.
								newHandle.ReferenceCount = objBasicInfo->HandleCount - 1;
							}
						}
					}
				}

				// Close the duplicate handle ofcourse.
				CloseHandle(hDup);
			}
		}
		
		// Free allocated query objects.
		VirtualFree(objBasicInfo, 0, MEM_RELEASE);
		VirtualFree(objInfo, 0, MEM_RELEASE);
	}
	
	// Free heap allocated handle information.
	VirtualFree(handleInfo, 0, MEM_RELEASE);
}