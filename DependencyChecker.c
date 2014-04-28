#include "DependencyChecker.h"

/*#pragma comment(lib, "depcheck_sdk/lib/DepCheck.lib")

// Initializes a depcheck result structure. After running this function its fully safe to use stack allocated result structures.
// To free a depcheck result structure initialized by this function, use the FreeDepCheckResult function.
void InitializeDepCheckResult(PDEPCHECKRESULT pResult)
{
	memset(pResult, 0, sizeof(DEPCHECKRESULT));
}

// Frees an allocated depcheck result structure.
void FreeDepCheckResult(PDEPCHECKRESULT pResult)
{
	VirtualFree(pResult->SystemInformationString, 0, MEM_RELEASE);
}

// Runs a dependency check on a file. The file will be loaded by the function itself and freed.
// Input filename is the file that will be loaded, output parameter holds the result.
// Returns TRUE if function succeeded and FALSE otherwise.
BOOL DependencyCheck(const char* fileName, PDEPCHECKRESULT pResult)
{
	IDepCheck* depCheck;
	
	// Create DepCheck interface.
	if(SUCCEEDED(DepCheckCreate(DEPCHECK_SDK_VERSION, &depCheck)))
	{
		BSTR sysInfo;
		
		// Retrieve system information string as start of the information sequence.
		if(depCheck->lpVtbl->SystemInfoString(depCheck, &sysInfo))
		{
			// Copy the string into the output result buffer and release original.
			const int wLength = wcslen(sysInfo);
			const int bLength = wLength * 2;
			pResult->SystemInformationString = (LPWSTR)VirtualAlloc(NULL, bLength, MEM_COMMIT, PAGE_READWRITE);
			memcpy(pResult->SystemInformationString, sysInfo, bLength);
			pResult->SystemInformationString[wLength] = 0;
			
			// Free depcheck allocated string.
			DepFreeString(sysInfo);
		}
		
		// Release DepCheck interface.
		depCheck->lpVtbl->Release(depCheck);
		return TRUE;
	}
	
	return FALSE;
}*/