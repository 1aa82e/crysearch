#ifndef _CrySearch_GlobalDef_h_
#define _CrySearch_GlobalDef_h_

#include "MemoryScanner.h"
#include "SettingsFile.h"
#include "AddressTable.h"
#include "NativeAPI.h"
#include "PortableExecutable.h"
#include "CryDebugger.h"

#include "CrySearchLibrary/SDK/CrySearch.h"

#ifdef _WIN64
	#pragma comment(lib, "CrySearchLibrary/Bin/x64/CrySearch64.lib")
#else
	#pragma comment(lib, "CrySearchLibrary/Bin/x86/CrySearch32.lib")
#endif

// ---------------------------------------------------------------------------------------------

// Defines the maximum size of a buffer allocated by the memory scanner that triggers a reduced 
// reallocation. The second definition is the reduced reallocation factor.
#define MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD		0x1000000 // 16 MB
#define MEMORY_SCANNER_BUFFER_REALLOCATION_FACTOR	(double)1.5

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

// ---------------------------------------------------------------------------------------------

// Type definition for memory reading function.
typedef const bool (__stdcall* CryReadMemoryRoutineType)(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize);
typedef const bool (__stdcall* CryWriteMemoryRoutineType)(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize);
typedef const bool (__stdcall* CryProtectMemoryRoutineType)(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess);

// CrySearch memory reading routines.
extern const bool __stdcall CryReadMemoryRoutine32(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize);
extern const bool __stdcall CryReadMemoryRoutineNt(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize);

// CrySearch memory writing routines.
extern const bool __stdcall CryWriteMemoryRoutine32(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize);
extern const bool __stdcall CryWriteMemoryRoutineNt(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize);

// CrySearch memory protection routines.
extern const bool __stdcall CryProtectMemoryRoutine32(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess);
extern const bool __stdcall CryProtectMemoryRoutineNt(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess);

// ---------------------------------------------------------------------------------------------

// CrySearch uses a few undocumented NT Internals functions. As they are used over different places in the application,
// a container globally defined keeps track of all of these.
__declspec(selectany) class _CrySearchRoutines
{
private:
	CryReadMemoryRoutineType ReadMemoryRoutine;
	CryWriteMemoryRoutineType WriteMemoryRoutine;
	CryProtectMemoryRoutineType ProtectMemoryRoutine;
public:	
	NtQuerySystemInformationPrototype NtQuerySystemInformation;
	NtQueryInformationThreadPrototype NtQueryInformationThread;
	NtQueryInformationProcessPrototype NtQueryInformationProcess;
	NtOpenProcessPrototype NtOpenProcess;
	NtQueryObjectPrototype NtQueryObject;
	NtReadVirtualMemoryPrototype NtReadVirtualMemory;
	NtWriteVirtualMemoryPrototype NtWriteVirtualMemory;
	NtProtectVirtualMemoryPrototype NtProtectVirtualMemory;
	
	// Construct all internals functions once for application wide use.
	_CrySearchRoutines();
	
	// Sets the routines from the settings file.
	void SetCrySearchReadMemoryRoutine(CryReadMemoryRoutineType read);
	void SetCrySearchWriteMemoryRoutine(CryWriteMemoryRoutineType write);
	void SetCrySearchProtectMemoryRoutine(CryProtectMemoryRoutineType protect);
	
	// Executes routines.
	const bool CryReadMemoryRoutine(HANDLE handle, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outSize) const;
	const bool CryWriteMemoryRoutine(HANDLE handle, LPVOID addr, LPCVOID buffer, SIZE_T size, SIZE_T* outSize) const;
	const bool CryProtectMemoryRoutine(HANDLE handle, LPVOID addr, SIZE_T size, ULONG newAccess, PULONG oldAccess) const;
	
} CrySearchRoutines;

// Initializes the routines from the settings file.
__declspec(noinline) void InitializeRoutines();

#endif