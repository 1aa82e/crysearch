#ifndef _CrySearch_GlobalDef_h_
#define _CrySearch_GlobalDef_h_

#include "MemoryScanner.h"
#include "SettingsFile.h"
#include "AddressTable.h"
#include "NativeAPI.h"
#include "PortableExecutable.h"
#include "CryDebugger.h"

// ---------------------------------------------------------------------------------------------

// Defines the amount of search results that CrySearch will keep in memory to view to the users.
// Be sure to also edit the amount in the string manually in the ScannerCompleted function.
#define MEMORYSCANNER_CACHE_LIMIT	100000

// Global variables for application wide access.
extern CryDebugger* mDebugger;
extern AddressTable loadedTable;
extern SettingsFile GlobalSettingsInstance;
extern MemoryScanner* mMemoryScanner;
extern PortableExecutable* mPeInstance;
extern Vector<Win32ModuleInformation> LoadedModulesList;
extern Win32PEInformation LoadedProcessPEInformation;
extern String TemporaryFolderPath;

// All features for proper destruction of objects is available but these are not always called on application shutdown.
// When CrySearch shuts down every opened application state must be restored. Force destruction on shutdown.
inline void CryGlobalDestruct()
{
	if (mDebugger)
	{
		mDebugger->Stop();
		delete mDebugger;
	}
	
	if (mPeInstance)
	{
		delete mPeInstance;
	}
};

// ArrayCtrl virtual rows need this convert structure to be able to dynamically retrieve its data.
template <String (GetData) (const int index)>
struct IndexBasedValueConvert : public Convert
{
	virtual Value Format(const Value& q) const
	{
		return GetData(int(q));
	}
};

// CrySearch uses a few undocumented NT Internals functions. As they are used over different places in the application,
// a container globally defined keeps track of all of these.
__declspec(selectany) struct _NtInternalFunctions
{
	NtQuerySystemInformationPrototype NtQuerySystemInformation;
	NtQueryInformationThreadPrototype NtQueryInformationThread;
	NtQueryInformationProcessPrototype NtQueryInformationProcess;
	NtOpenProcessPrototype NtOpenProcess;
	
	// Construct all internals functions once for application wide use.
	_NtInternalFunctions()
	{
		HMODULE ntdll = GetModuleHandle("ntdll.dll");
		this->NtQuerySystemInformation = (NtQuerySystemInformationPrototype)GetProcAddress(ntdll, "NtQuerySystemInformation");
		this->NtQueryInformationThread = (NtQueryInformationThreadPrototype)GetProcAddress(ntdll, "NtQueryInformationThread");
		this->NtQueryInformationProcess = (NtQueryInformationProcessPrototype)GetProcAddress(ntdll, "NtQueryInformationProcess");
		this->NtOpenProcess = (NtOpenProcessPrototype)GetProcAddress(ntdll, "NtOpenProcess");
	}
} NtInternalFunctions;

// Multiple parts of CrySearch may want to check whether a value is a multiple of another value.
extern "C" inline const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal);

#endif