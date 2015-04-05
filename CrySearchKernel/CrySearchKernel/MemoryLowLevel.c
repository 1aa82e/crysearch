#include <ntifs.h>
#include "MemoryLowLevel.h"

// Reads a memory block from the process specified by procId. Returns STATUS_SUCCESS if the operation succeeded and
// an error value if otherwise.
const NTSTATUS CryReadProcessMemory(const int procId, const void* pAddress, void* const pOutBuffer, const DWORD readSize)
{
	PEPROCESS pProcess;
	NTSTATUS retVal;
	PKAPC_STATE apcState = NULL;

	// Look up the process object using the process ID.
	retVal = PsLookupProcessByProcessId((HANDLE)procId, &pProcess);
	if (retVal != STATUS_SUCCESS)
	{
		return retVal;
	}

	__try
	{
		// Allocate APC state block.
		apcState = ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE));

		__try
		{
			// Attach the current thread to the address space of the process.
			KeStackAttachProcess(pProcess, apcState);

			// Copy the memory block to the specified buffer.
			RtlCopyMemory(pOutBuffer, pAddress, readSize);
			retVal = STATUS_SUCCESS;
		}
		__finally
		{
			// Detach the process and free the APC state block.
			KeUnstackDetachProcess(apcState);
			ExFreePool(apcState);
		}
	}
	__except (1)
	{
		retVal = STATUS_UNSUCCESSFUL;
	}

	// Dereference the process object pointer.
	ObDereferenceObject(pProcess);
	return retVal;
}