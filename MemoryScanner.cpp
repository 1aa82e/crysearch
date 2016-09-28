#include "MemoryScanner.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"

#include <Psapi.h>

// The synchronisation primitives.
StaticMutex CacheMutex;

// Globally used scanning variables. Declared globally to speed up calls and variable access.
ScanParameterBase* GlobalScanParameter;

// Cache vectors that contain the data visible in the GUI ArrayCtrl.
Vector<SearchResultCacheEntry> CachedAddresses;

// Deletes all temporary files created from the temp folder.
void DeleteTemporaryFiles()
{
	const char* temp = mMemoryScanner->GetTempFolderPath();
	for (int i = 1; i <= mMemoryScanner->GetSystemThreadCount(); ++i)
	{
		FileDelete(AppendFileName(temp, Format("Addresses%i.temp", i)));
		FileDelete(AppendFileName(temp, Format("Values%i.temp", i)));
	
		FileDelete(AppendFileName(temp, Format("Addresses%i.tempSCANNING", i)));
		FileDelete(AppendFileName(temp, Format("Values%i.tempSCANNING", i)));
	}
}

// Adds a set of new search results to the cache vectors. Up to a million results are kept in memory for GUI visibility.
void AddResultsToCache(const int Resultcount, const SIZE_T* AddressBuffer, const Byte* lengthBuffers)
{
	// While the count is not yet bigger than the threshold, we may copy the entries into the cache.
	const int possible = MEMORYSCANNER_CACHE_LIMIT - CachedAddresses.GetCount();
	if (possible > 0)
	{
		// Lock access to the cache vector.
		CacheMutex.Enter();
		
		// Add entries to the cache.
		const int minIt = min(possible, Resultcount);
		for (int i = 0; i < minIt; ++i)
		{
			// Find out whether this address points inside a loaded module. Tardy this way, but this is most accurate.
			const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(AddressBuffer[i]);
			
			// Add the cache values to the appropriate buffer.
			SearchResultCacheEntry& entry = CachedAddresses.Add(SearchResultCacheEntry(AddressBuffer[i], !!mod));

			// If the string length is specified, add it to the search result identifier.
			if (lengthBuffers)
			{
				entry.StringLength = lengthBuffers[i];
			}
		}

		// Release the lock.
		CacheMutex.Leave();
	}
}

// ---------------------------------------------------------------------------------------------

// MemoryScanner class default constructor.
MemoryScanner::MemoryScanner()
{
	this->mSettingsInstance = SettingsFile::GetInstance();
	this->ScanRunning = false;
	this->mLoadedProcessId = 0;
	this->mScanResultCount = 0;
	this->threadCount = CPU_Cores();
	this->mProcessSuspended = false;
	this->mOpenedProcessHandle = NULL;
	this->mReadOnly = false;
	
	// Adjust CrySearch process token for it to be able to debug protected processes and load drivers.
	HANDLE hToken = NULL;
	
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	
	LUID luid;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	
	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid.HighPart = luid.HighPart;
	tokenPriv.Privileges[0].Luid.LowPart = luid.LowPart;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	// On Windows XP this should work without further notice, but on any higher version you might need to run CrySearch as Administrator.
	AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	
	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &luid);
	
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid.HighPart = luid.HighPart;
	tokenPriv.Privileges[0].Luid.LowPart = luid.LowPart;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	CloseHandle(hToken);
}

// MemoryScanner class default destructor.
MemoryScanner::~MemoryScanner()
{
	this->CloseProcess();
}

// Closes the process in the memory scanner, meaning closing the handles and resetting identification values.
// SEH construction for the fucking annoying CloseHandle error when there is no process yet opened before application closure.
void MemoryScanner::CloseProcess()
{
#ifdef _DEBUG
	__try
	{
#endif
		this->mLoadedProcessId = 0;
		CloseHandle(this->mOpenedProcessHandle);
		this->mOpenedProcessHandle = NULL;
#ifdef _DEBUG
	}
	__except(EXCEPTION_EXECUTE_HANDLER) { }
#endif
}

// Returns the runtime-allocated temporary files path.
const char* MemoryScanner::GetTempFolderPath() const
{
	// Stores temp path of the current session. A change of temp folder requires CrySearch restart.
	static String mTemporaryFolderPath = GetTempPath();
	return mTemporaryFolderPath;
}

// Returns the amount of threads the processor logically has, thus the application may use simultaniously.
const int MemoryScanner::GetSystemThreadCount() const
{
	return this->threadCount;
}

// Open an existing process by process ID.
// Returns true if the process succesfully opened and false if it did not.
bool MemoryScanner::InitializeExistingProcess(const int processId, const char* exeTitle, const bool readOnly)
{
	// Construct process open flags based on the selected operation mode.
	DWORD openFlags = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
	if (!readOnly)
	{
		openFlags |= PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE;
	}
	
	// Select the configured routine for opening the process and execute it.
	const int opr = this->mSettingsInstance->GetOpenProcessRoutine();
	if (opr == ROUTINE_OPENPROCESS)
	{
		// Use the default kernel32.dll OpenProcess function to obtain a process handle.
		this->mOpenedProcessHandle = OpenProcess(openFlags, FALSE, processId);
	}
	else if (opr == ROUTINE_NTOPENPROCESS)
	{
		// Use the ntdll.dll NtOpenProcess function to obtain a process handle.
		CLIENT_ID cid = { (HANDLE)processId, 0 };
		
		OBJECT_ATTRIBUTES objAttr;
		InitializeObjectAttributes(&objAttr, NULL, 0, 0, NULL);
		   
		if (!CrySearchRoutines.NtOpenProcess)
		{
			this->ErrorOccured(NATIVEROUTINEGETPROCFAILED);
			return false;
		}
		
		CrySearchRoutines.NtOpenProcess(&this->mOpenedProcessHandle, openFlags, &objAttr, &cid);
	}
	else if (opr > 1)
	{
		// Use plugin-defined routine to obtain process handle.
		Vector<CrySearchPlugin> plugins;
		mPluginSystem->GetPluginsByType(CRYPLUGIN_COREFUNC_OVERRIDE, plugins);
		const int opr2 = opr - 2;
		if (opr2 < plugins.GetCount())
		{
			// Retrieve pointer to the plugin routine.
			CryOpenProcessRoutineType routine = (CryOpenProcessRoutineType)GetProcAddress(plugins[opr2].BaseAddress, "CryOpenProcessRoutine");
			if (routine)
			{
				// Routine is present, execute it.
				this->mOpenedProcessHandle = routine(openFlags, FALSE, processId);
			}
			else
			{
				// Failed to retrieve a pointer to the routine.
				return false;
			}
		}
	}
	
	// Validate the handle and process handle before confirming.
	if (!this->mOpenedProcessHandle || this->mOpenedProcessHandle == INVALID_HANDLE_VALUE)
	{
		this->ErrorOccured(OPENPROCESSFAILED);
		return false;
	}
	
	// Process succesfully loaded, set identifiers and return.
	this->mLoadedProcessId = processId;
	this->isX86Process = IsI386Process(this->mOpenedProcessHandle);
	this->mReadOnly = readOnly;

	// If a process was opened by dragging the cursor onto another window, the process name is empty from the start.
	if (!exeTitle)
	{
		char procTitle[MAX_PATH];
		GetProcessImageFileName(this->mOpenedProcessHandle, procTitle, MAX_PATH);
		this->mProcessName = GetFileName(procTitle);
	}
	else
	{
		this->mProcessName = exeTitle;
	}
	
	return true;
}

// Create a new process using CreateProcess, putting the process ID of the created process in the 2nd parameter.
// Returns true if the process succesfully created and opened and false if it did not.
bool MemoryScanner::InitializeNewProcess(const char* exetitle, const DWORD flags, const char* args, int* const pProcessId)
{
	// Prepare input parameters.
	STARTUPINFO info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;
	String cmdArgs = GetFileName(exetitle);
	
	// Append the arguments to the command line string.
	if (args)
	{
		cmdArgs += 0x20;
		cmdArgs += args;
	}
	
	// Create process with specified flags and command line arguments.
	bool b = !!CreateProcess(exetitle, args ? const_cast<char*>(cmdArgs.Begin()) : NULL, NULL, NULL, FALSE, flags, NULL, NULL, &info, &processInfo);
	if (b)
	{
		// Save operative information for the memoryscanner.
		this->mOpenedProcessHandle = processInfo.hProcess;
		*pProcessId = processInfo.dwProcessId;
		this->mLoadedProcessId = processInfo.dwProcessId;
		CloseHandle(processInfo.hThread);
	}
	
	// Set additional internal process indication fields.
	this->mProcessSuspended = (flags & CREATE_SUSPENDED) ? true : false;
	this->isX86Process = IsI386Process(this->mOpenedProcessHandle);
	this->mProcessName = GetFileName(exetitle);
	
	return b;
}

// Sets the internal process suspended state indicator.
void MemoryScanner::ResetSuspendedState()
{
	this->mProcessSuspended = false;
}

// Gets whether the opened process is suspended or not. The suspended flag is reset upon close
// and after a created process has left suspended state by CrySearch operations.
const bool MemoryScanner::IsProcessSuspended() const
{
	return this->mProcessSuspended;
}

// Returns the name of the opened process.
const String& MemoryScanner::GetProcessName() const
{
	return this->mProcessName;
}

// Returns whether the process that has loaded is a x86 process or a x64 process.
const bool MemoryScanner::IsX86Process() const
{
	return this->isX86Process;
}

// Returns the process ID associated to the memory scanner. If there is no process opened the return value is 0.
const int MemoryScanner::GetProcessId() const
{
	return this->mLoadedProcessId;
}

// Returns the process handle associated to the memory scanner. If there is no process opened the return value is NULL.
HANDLE MemoryScanner::GetHandle() const
{
	return this->mOpenedProcessHandle;
}

// Returns whether the memory scanner is currently running a scan or not.
bool MemoryScanner::IsScanRunning() const
{
	return this->ScanRunning;
}

// Returns the number of scan results.
const int MemoryScanner::GetScanResultCount() const
{
	return this->mScanResultCount;
}

// Returns the number of finished regions.
const int MemoryScanner::GetRegionFinishedCount() const
{
	return this->mRegionFinishCount;
}

// Returns whether the memory scanner is operating in read-only mode.
const bool MemoryScanner::IsReadOnlyOperationMode() const
{
	return this->mReadOnly;
}

// Checks whether all workers are done with scanning jobs.
const bool MemoryScanner::GetIsWorkCompleted() const
{
	for (auto const& worker : this->mWorkerFileOrder)
	{
		// If there is still work in progress, return false.
		if (!worker.FinishedWork)
		{
			return false;
		}
	}
	
	// All workers are done!
	return true;
}

// Tells the memory scanner that it can clean up whatever resources were used during a memory scan.
void MemoryScanner::SetWorkCompleted()
{
	// Destruct the compare functor used for the recent memory scan.
	delete this->mCompareValues;
	this->mCompareValues = NULL;
	
	// Set the scanner to not running.
	this->ScanRunning = false;
}

// Compare functions

template <>
bool __fastcall CompareGreater(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <typename T>
bool __fastcall CompareGreater(const T& input, const T& expected)
{
	return (input > expected);
}

template <>
bool __fastcall CompareSmaller(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <typename T>
bool __fastcall CompareSmaller(const T& input, const T& expected)
{
	return (input < expected);
}

template <>
bool __fastcall CompareEqual(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	return false;
}

template <>
bool __fastcall CompareEqual(const float& input, const float& expected)
{
	return (((int)input) == ((int)expected));
}

template <>
bool __fastcall CompareEqual(const double& input, const double& expected)
{
	return (((int)input) == ((int)expected));
}

template <typename T>
bool __fastcall CompareEqual(const T& input, const T& expected)
{
	return (input == expected);
}

template <typename T>
bool __fastcall CompareUnknownInitialValue(const T& input, const T& expected)
{
	// Unknown initial value should return everything that is found by the scanner.
	return true;
}

// Compares ANSI and Unicode strings until a null character was found.
bool __fastcall CompareStringNullCharA(const char* input, const int inputLength, const char* expected, int* const outputLength)
{
	if (memcmp(input, expected, inputLength) == 0)
	{
		const char* iterator = input + inputLength;
		const int endIterator = STRING_MAX_UNTIL_NULL - inputLength;
		int i = 0;
		while (*iterator != 0 && i < endIterator)
		{
			++iterator;
			++i;
		}
		*outputLength = i + inputLength;
		return true;
	}
	
	return false;
}

bool __fastcall CompareStringNullCharW(const wchar* input, const int inputLength, const wchar* expected, int* const outputLength)
{
	if (memcmp(input, expected, inputLength) == 0)
	{
		const wchar* iterator = input + inputLength;
		const int endIterator = STRING_MAX_UNTIL_NULL - inputLength;
		int i = 0;
		while (*iterator != 0 && i < endIterator)
		{
			++iterator;
			++i;
		}
		*outputLength = i + inputLength / sizeof(wchar);
		return true;
	}
	
	return false;
}

// Clears the search results currently in cache and deletes all temporary files created.
void MemoryScanner::ClearSearchResults()
{
	// Always delete the temporary files. Even if writes failed, the files can be there, causing problems.
	DeleteTemporaryFiles();
	
	if (this->mScanResultCount > 0)
	{
		this->mScanResultCount = 0;
		CachedAddresses.Clear();
	}
	
	// Clear worker parameter data.
	this->mWorkerFileOrder.Clear();
}

// Worker function that implements specialized behavior for double types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const double& value)
{
	// Create output files, the destructor will close them.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileOut valFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData->WorkerIdentifier)));
	
	const int fastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(int) : 1;
	unsigned int fileIndex = 0;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	double* localValues = new double[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	unsigned int arrayIndex = 0;

	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int resultCounter = 0;
		MemoryRegion& currentRegion = this->memRegions[i];
		const SIZE_T regionSize = currentRegion.MemorySize;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < regionSize; i += fastScanAlignSize)
			{
				const double* tempStore = (double*)&(buffer[i]);
				
				if ((*reinterpret_cast<ValueComparator<double>*>(this->mCompareValues))(*tempStore, value))
				{
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					localValues[arrayIndex++] = *tempStore;
					
					// Increment result counters for file and I/O.
					++fileIndex;
					++resultCounter;
					
					// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
					if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
					{
						// Check whether we have to cache some more search results in the user interface.
						if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
						{
							AddResultsToCache(arrayIndex, localAddresses, NULL);
						}
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
						valFile.Put(localValues, arrayIndex * sizeof(double));
												
						// Reset the array index, we reuse the buffers in memory.
						arrayIndex = 0;
					}
				}
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->mScanResultCount += resultCounter;
		currentRegion.FileDataIndexes.ResultCount = resultCounter;
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, NULL);
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
		valFile.Put(localValues, arrayIndex * sizeof(double));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	delete[] localValues;
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Worker function that implements specialized behavior for byte-array types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const ArrayOfBytes& value)
{
	// Create output file, the destructor will close it.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	
	unsigned int fileIndex = 0;
	const Byte* const inputData = value.Data;
	const int inputLength = value.Size;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int resultCounter = 0;
		MemoryRegion& currentRegion = this->memRegions[i];
		const SIZE_T regionSize = currentRegion.MemorySize;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < regionSize; ++i)
			{
				Byte* tempStore = &(buffer[i]);
				
				if (memcmp(tempStore, inputData, inputLength) == 0)
				{
					localAddresses[arrayIndex++] = currentRegion.BaseAddress + i;
					
					// Increment result counters for file and I/O.
					++fileIndex;
					++resultCounter;
					
					// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
					if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
					{
						// Check whether we have to cache some more search results in the user interface.
						if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
						{
							AddResultsToCache(arrayIndex, localAddresses, NULL);
						}
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
						
						// Reset the array index, we reuse the buffers in memory.
						arrayIndex = 0;
					}
				}
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->mScanResultCount += resultCounter;
		currentRegion.FileDataIndexes.ResultCount = resultCounter;
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, NULL);
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Worker function that implements specialized behavior for Unicode string types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const WString& value)
{
	// Create output file, the destructor will close it.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	
	unsigned int fileIndex = 0;
	const wchar* const inputData = value.Begin();
	const int inputLengthInChars = value.GetLength();
	const int inputLength = value.GetLength() * sizeof(wchar);
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;

	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int resultCounter = 0;
		MemoryRegion& currentRegion = this->memRegions[i];
		const SIZE_T regionSize = currentRegion.MemorySize;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < regionSize; ++i)
			{
				const wchar* strPtr = (wchar*)&(buffer[i]);
				
				int outputLength = inputLengthInChars;
				if (localNullScan ? CompareStringNullCharW(strPtr, inputLength, inputData, &outputLength) : (memcmp(strPtr, inputData, inputLength) == 0))
				{
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					stringLengthsArray[arrayIndex++] = outputLength;
					
					// Increment result counters for file and I/O.
					++fileIndex;
					++resultCounter;
					
					// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
					if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
					{
						// Check whether we have to cache some more search results in the user interface.
						if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
						{
							AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
						}
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
						
						// Reset the array index, we reuse the buffers in memory.
						arrayIndex = 0;
					}
				}
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->mScanResultCount += resultCounter;
		currentRegion.FileDataIndexes.ResultCount = resultCounter;
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Worker function that implements specialized behavior for ANSI string types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const String& value)
{
	// Create output file, the destructor will close it.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	
	unsigned int fileIndex = 0;
	const char* const inputData = value.Begin();
	const int inputLength = value.GetLength();
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const SIZE_T regionSize = currentRegion.MemorySize;
		unsigned int resultCounter = 0;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;

		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < regionSize; ++i)
			{
				const char* strPtr = (char*)&(buffer[i]);
				
				int outputLength = inputLength;
				if (localNullScan ? CompareStringNullCharA(strPtr, inputLength, inputData, &outputLength) : (memcmp(strPtr, inputData, inputLength) == 0))
				{
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					stringLengthsArray[arrayIndex++] = outputLength;
					
					// Increment result counters for file and I/O.
					++fileIndex;
					++resultCounter;
					
					// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
					if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
					{
						// Check whether we have to cache some more search results in the user interface.
						if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
						{
							AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
						}
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
						
						// Reset the array index, we reuse the buffers in memory.
						arrayIndex = 0;
					}
				}
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->mScanResultCount += resultCounter;
		currentRegion.FileDataIndexes.ResultCount = resultCounter;
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Represents the default template worker function for the set of workers including specialized ones.
// This set of workers run the first scan sequence.
template <typename T>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const T& value)
{
#ifdef _DEBUG
	LARGE_INTEGER frequency;
	LARGE_INTEGER t1;
	LARGE_INTEGER t2;
	
	// Get the amount of ticks per second.
	QueryPerformanceFrequency(&frequency);

	// Start the timer.
	QueryPerformanceCounter(&t1);
#endif

	// -------------------------------------------------
	
	// Create output files, the destructor will close them.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileOut valFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData->WorkerIdentifier)));
	
	int fastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(T) : 1;
	if (fastScanAlignSize == sizeof(__int64))
	{
		fastScanAlignSize = sizeof(int);
	}
	
	unsigned int fileIndex = 0;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	T* localValues = new T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	unsigned int arrayIndex = 0;
		
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const SIZE_T regionSize = currentRegion.MemorySize;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		unsigned int resultCounter = 0;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < regionSize; i += fastScanAlignSize)
			{
				const T* tempStore = (T*)&(buffer[i]);

				if ((*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*tempStore, value))
				{
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					localValues[arrayIndex++] = *tempStore;
					
					// Increment result counters for file and I/O.
					++fileIndex;
					++resultCounter;
					
					// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
					if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
					{
						// Check whether we have to cache some more search results in the user interface.
						if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
						{
							AddResultsToCache(arrayIndex, localAddresses, NULL);
						}
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
						valFile.Put(localValues, arrayIndex * sizeof(T));
												
						// Reset the array index, we reuse the buffers in memory.
						arrayIndex = 0;
					}
				}
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->mScanResultCount += resultCounter;
		currentRegion.FileDataIndexes.ResultCount = resultCounter;
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, NULL);
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
		valFile.Put(localValues, arrayIndex * sizeof(T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	delete[] localValues;
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
	
	// -------------------------------------------------

#ifdef _DEBUG
	// Stop the timer.
	QueryPerformanceCounter(&t2);
	OutputDebugString(Format("Worker %i took %f ms\r\n", regionData->WorkerIdentifier, (t2.QuadPart - t1.QuadPart) * 1000.0 / frequency.QuadPart));
#endif
}

// Initializes the first scan sequence. Call this function from the user interface.
template <typename T>
void MemoryScanner::FirstScan()
{
	// Clear last scan's results.
	this->ClearSearchResults();

	SIZE_T incAddress = 0;
	MEMORY_BASIC_INFORMATION block;
	SIZE_T totalMemorySize = 0;
	
	this->memRegions.Clear();
	this->ScanRunning = true;
	
	// Query virtual pages inside target process.
	while (VirtualQueryEx(this->mOpenedProcessHandle, (void*)incAddress, &block, sizeof(block)))
	{
		// Check whether region is readable and exclude scan types that are not wanted.
		if ((block.State == MEM_COMMIT) && (!(block.Protect & PAGE_GUARD)) && (!(block.Protect & PAGE_NOACCESS))
			&& ((this->mSettingsInstance->GetScanMemPrivate() & (block.Type == MEM_PRIVATE))
			|| (this->mSettingsInstance->GetScanMemImage() & (block.Type == MEM_IMAGE))
			|| (this->mSettingsInstance->GetScanMemMapped() & (block.Type == MEM_MAPPED))))
	    {
	        // Check protection constants to see whether the region should be scanned or not.
	        if ((this->mSettingsInstance->GetScanWritableMemory() & ((block.Protect & MEM_WRITABLE) != 0))
	        	|| (this->mSettingsInstance->GetScanExecutableMemory() & ((block.Protect & MEM_EXECUTABLE) != 0))
	        	|| (this->mSettingsInstance->GetScanCopyOnWriteMemory() & ((block.Protect & MEM_COPYONWRITE) != 0)))
	     	{
	     		// Increment the total size of readable memory.
	     		totalMemorySize += block.RegionSize;
	     		
	     		// Memory region is valid for scanning, add it to the region list.
		        MemoryRegion memReg;
		        memReg.BaseAddress = (SIZE_T)block.BaseAddress;
			    memReg.MemorySize = block.RegionSize;
			    this->memRegions << memReg;
			}
	    }
	
		const SIZE_T oldIncAddress = incAddress;
	    incAddress = (SIZE_T)block.BaseAddress + block.RegionSize;
	    
	    // Compatibility issue between wow64 and x64 processes on some systems causes infinite loop.
		if (oldIncAddress > (SIZE_T)block.BaseAddress)
		{
			break;
		}
	}
	
	// Check if the process was terminated. If it was, display a gentle error message and finalize UI properly.
	if (GetLastError() == ERROR_ACCESS_DENIED)
	{
		this->ErrorOccured(PROCESSWASTERMINATED);
		this->ScanRunning = false;

		return;
	}
	
	// Set thread finish count to 0. This is needed to restart progress indication.
	this->mRegionFinishCount = 0;
	
	// Check for sets of regions and append overlapping regions to reduce the number of regions needed to read.
	for (int i = 0; i < this->memRegions.GetCount(); i++)
	{
		// Append new region to other region if possible.
		const int prev = i - 1;
		if ((i > 0) && (this->memRegions[i].BaseAddress == (this->memRegions[prev].BaseAddress + this->memRegions[prev].MemorySize)))
		{
			this->memRegions[prev].MemorySize += this->memRegions[i].MemorySize;
			this->memRegions.Remove(i--);
		}
	}
	
	// Abort scanning and throw an error, no readable memory found.
	if (this->memRegions.GetCount() <= 0)
	{
		this->ErrorOccured(NOREADABLEMEMORYFOUND);
		this->ScanRunning = false;
		
		return;
	}
	
	// Start worker threads using the regions that are found and readable.
#ifdef _MULTITHREADED
	this->mThreadPool.SetThreadPriority(this->mSettingsInstance->GetScanThreadPriority());
#endif

	// Signal user interface with a count to set progress indicator to ready state.
	const int regionCount = this->memRegions.GetCount();
	this->ScanStarted(regionCount);
	
	// Assign compare function accordingly
	this->mCompareValues = new ValueComparator<T>(GlobalScanParameter->GlobalScanType);

	const SIZE_T workerAmount = totalMemorySize / threadCount;
	SIZE_T memoryCounter = 0;
	int regionIndex = 0;
	int oldRegionIndex = 0;
	
	// Walk the memory pages list and divide the operable memory as efficiently as possible.
	for (int i = 0; i < threadCount;)
	{
		while (memoryCounter < workerAmount && regionIndex < regionCount)
		{
			memoryCounter += memRegions[regionIndex++].MemorySize;
		}
		
		WorkerRegionParameterData& regionData = this->mWorkerFileOrder.Add();
		regionData.OriginalStartIndex = oldRegionIndex;
		regionData.Length = regionIndex - oldRegionIndex;
		regionData.WorkerIdentifier = ++i;
		
		oldRegionIndex = regionIndex;
		memoryCounter = 0;
	}
	
	// If there is a remainder, add it to the last worker.
	const int remainder = regionCount - oldRegionIndex;
	if (remainder)
	{
		this->mWorkerFileOrder[this->mWorkerFileOrder.GetCount() - 1].Length += remainder;
	}
	
	// Launch the workers.
	for (auto& work : this->mWorkerFileOrder)
	{
		this->mThreadPool & THISBACK2(FirstScanWorker<T>, &work, ((T)(reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->ScanValue));
	}
}

// This function contains specialized behavior for byte-array types.
template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const ArrayOfBytes& value)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileIn oldAddrFile(addrFileOld);

	unsigned int fileIndex = 0;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;

	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		unsigned int resultCounter = 0;
		
		// Are there any search results for this page?
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				oldAddrFile.Seek(oldFileIndex * sizeof(SIZE_T));
				oldAddrFile.Get(addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T));
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; ++resultIndex)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					Byte* currentDataPtr = buffer + (currentResultPtr - currentRegion.BaseAddress);
					
					if (memcmp(currentDataPtr, value.Data, value.Size) == 0)
					{
						localAddresses[arrayIndex++] = currentResultPtr;
						
						// Increment result counters for file and I/O.
						++fileIndex;
						++resultCounter;
						
						// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
						if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
						{
							// Check whether we have to cache some more search results in the user interface.
							if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
							{
								AddResultsToCache(arrayIndex, localAddresses, NULL);
							}
							
							// Write memory buffers out to file.
							addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
							
							// Reset the array index, we reuse the buffers in memory.
							arrayIndex = 0;
						}
					}
				}
				
				delete[] addressesFileBuffer;
			}
			
			delete[] buffer;
			
			// Update counters and user interface components.
			this->mScanResultCount += resultCounter;
			currentRegion.FileDataIndexes.ResultCount = resultCounter;
		}

		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, NULL);
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// This function contains specialized behavior for Unicode string types.
template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const WString& value)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileIn oldAddrFile(addrFileOld);

	unsigned int fileIndex = 0;
	const int inputLengthInChars = value.GetLength();
	const int inputLength = value.GetLength() * sizeof(wchar);
	const wchar* const inputData = value.Begin();
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		unsigned int resultCounter = 0;
		
		// Are there any search results for this page?
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				oldAddrFile.Seek(oldFileIndex * sizeof(SIZE_T));
				oldAddrFile.Get(addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T));
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; ++resultIndex)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					const wchar* currentDataPtr = (wchar*)(buffer + (currentResultPtr - currentRegion.BaseAddress));
					
					if (memcmp(currentDataPtr, inputData, inputLength) == 0)
					{
						localAddresses[arrayIndex] = currentResultPtr;
						stringLengthsArray[arrayIndex++] = inputLengthInChars;
						
						// Increment result counters for file and I/O.
						++fileIndex;
						++resultCounter;
						
						// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
						if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
						{
							// Check whether we have to cache some more search results in the user interface.
							if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
							{
								AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
							}
							
							// Write memory buffers out to file.
							addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
							
							// Reset the array index, we reuse the buffers in memory.
							arrayIndex = 0;
						}
					}
				}
				
				delete[] addressesFileBuffer;
			}
			
			delete[] buffer;

			// Update counters and user interface components.
			this->mScanResultCount += resultCounter;
			currentRegion.FileDataIndexes.ResultCount = resultCounter;
		}

		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// This function contains specialized behavior for ANSI string types.
template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const String& value)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileIn oldAddrFile(addrFileOld);

	unsigned int fileIndex = 0;
	const int inputLength = value.GetLength();
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		unsigned int resultCounter = 0;
		
		// Are there any search results for this page?
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				oldAddrFile.Seek(oldFileIndex * sizeof(SIZE_T));
				oldAddrFile.Get(addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T));
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; ++resultIndex)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					const char* currentDataPtr = (char*)(buffer + (currentResultPtr - currentRegion.BaseAddress));
					
					if (memcmp(currentDataPtr, value, inputLength) == 0)
					{
						localAddresses[arrayIndex] = currentResultPtr;
						stringLengthsArray[arrayIndex++] = inputLength;
						
						// Increment result counters for file and I/O.
						++fileIndex;
						++resultCounter;
						
						// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
						if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
						{
							// Check whether we have to cache some more search results in the user interface.
							if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
							{
								AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
							}
							
							// Write memory buffers out to file.
							addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
							
							// Reset the array index, we reuse the buffers in memory.
							arrayIndex = 0;
						}
					}
				}
				
				delete[] addressesFileBuffer;
			}
			
			delete[] buffer;

			// Update counters and user interface components.
			this->mScanResultCount += resultCounter;
			currentRegion.FileDataIndexes.ResultCount = resultCounter;
		}

		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// This function is the default template for the set of specialized workers for the next scan.
template <typename T>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const T& value)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));
	const String valuesFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.tempSCANNING", regionData->WorkerIdentifier));
	
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileOut valFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData->WorkerIdentifier)));

	FileIn oldAddrFile(addrFileOld);
	FileIn oldValuesFile;
	
	// This part is crucial for the comparison scan types (CHANGED, UNCHANGED, INCREASED, DECREASED) to work!
	if (GlobalScanParameter->GlobalScanType >= SCANTYPE_CHANGED)
	{
		oldValuesFile.Open(valuesFileOld);
	}

	unsigned int fileIndex = 0;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	SIZE_T* localAddresses = new SIZE_T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	T* localValues = new T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	unsigned int arrayIndex = 0;
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		unsigned int resultCounter = 0;
		unsigned int oldTempFileIndex = 0;
		
		// Are there any search results for this page?
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				oldAddrFile.Seek(oldFileIndex * sizeof(SIZE_T));
				oldAddrFile.Get(addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T));

				T* valuesFileBuffer = NULL;
				
				// If the user selected a scan type that requires comparison against saved search results, we need to load the file from disk.
				if ((int)GlobalScanParameter->GlobalScanType >= (int)SCANTYPE_CHANGED)
				{
					valuesFileBuffer = new T[currentRegion.FileDataIndexes.ResultCount];
					oldValuesFile.Seek(oldFileIndex * sizeof(T));
					oldValuesFile.Get(valuesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(T));
				}
				
				// Walk through the saved search results.
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; resultIndex++)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					const T* currentDataPtr = (T*)(buffer + (currentResultPtr - currentRegion.BaseAddress));
					
					// Compare the current and saved values with whatever configured comparetor.
					bool compareSucceeded = false;
					if (GlobalScanParameter->GlobalScanType == SCANTYPE_CHANGED)
					{
						compareSucceeded = !(*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*currentDataPtr, valuesFileBuffer[oldTempFileIndex]);
					}
					else if (GlobalScanParameter->GlobalScanType >= (int)SCANTYPE_UNCHANGED)
					{
						compareSucceeded = (*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*currentDataPtr, valuesFileBuffer[oldTempFileIndex]);
					}
					else
					{
						compareSucceeded = (*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*currentDataPtr, value);
					}
					
					// Whether the comparison succeeded or not, this seperate array index always has to be incremented.
					++oldTempFileIndex;

					if (compareSucceeded)
					{
						localAddresses[arrayIndex] = currentResultPtr;
						localValues[arrayIndex++] = *currentDataPtr;
						
						// Increment result counters for file and I/O.
						++fileIndex;
						++resultCounter;
						
						// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
						if (arrayIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
						{
							// Check whether we have to cache some more search results in the user interface.
							if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
							{
								AddResultsToCache(arrayIndex, localAddresses, NULL);
							}
							
							// Write memory buffers out to file.
							addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
							valFile.Put(localValues, arrayIndex * sizeof(T));
													
							// Reset the array index, we reuse the buffers in memory.
							arrayIndex = 0;
						}
					}
				}
				
				delete[] addressesFileBuffer;
				
				if (valuesFileBuffer)
				{
					delete[] valuesFileBuffer;
				}
			}
			
			delete[] buffer;

			// Update counters and user interface components.
			this->mScanResultCount += resultCounter;
			currentRegion.FileDataIndexes.ResultCount = resultCounter;
		}

		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If necessary, close the old values file.
	if (oldValuesFile.IsOpen())
	{
		oldValuesFile.Close();
	}
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// If the buffer was never entirely filled, we still need to flush it to disk.
	if (arrayIndex > 0 && arrayIndex < MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		// Check whether we have to cache some more search results in the user interface.
		if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
		{
			AddResultsToCache(arrayIndex, localAddresses, NULL);
		}
		
		// Write memory buffers out to file.
		addressesFile.Put(localAddresses, arrayIndex * sizeof(SIZE_T));
		valFile.Put(localValues, arrayIndex * sizeof(T));
	}
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	delete[] localValues;

	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	FileDelete(valuesFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Initializes the next scan sequence. Call this function from the user interface.
template <typename T>
void MemoryScanner::NextScan()
{
	// Clear partial search results for next scanning.
	this->mScanResultCount = 0;
	CachedAddresses.Clear();
	
	this->ScanRunning = true;
	
	// Use the existing workers to refresh the scan results.
	for (int i = 1; i <= threadCount; i++)
	{
		String addrFn = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", i));
		String valFn = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", i));
		
		// If the scan is a string, wstring or aob, the values file is not required.
		if (GlobalScanParameter->GlobalScanValueType >= VALUETYPE_STRING)
		{
			if (!FileExists(addrFn))
			{
				ClearSearchResults();
			
				this->ErrorOccured(DATAFILENOTFOUND);
				this->ScanRunning = false;

				return;
			}
			
			FileMove(addrFn, AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", i)));
		}
		else
		{
			// If one of the data files are deleted, the scan should not start in order to prevent crashing.
			if (!FileExists(addrFn) || !FileExists(valFn))
			{
				ClearSearchResults();
				
				this->ErrorOccured(DATAFILENOTFOUND);
				this->ScanRunning = false;
			
				return;
			}
			
			FileMove(addrFn, AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", i)));
			FileMove(valFn, AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.tempSCANNING", i)));
		}
	}
	
	// Reset progress indication bar in the GUI.
	this->mRegionFinishCount = 0;
	this->ScanStarted(this->memRegions.GetCount());
	
	// Assign compare function accordingly
	this->mCompareValues = new ValueComparator<T>(GlobalScanParameter->GlobalScanType);
	
	// Set thread priority for the workers ran by this scan session.
#ifdef _MULTITHREADED
	this->mThreadPool.SetThreadPriority(this->mSettingsInstance->GetScanThreadPriority());
#endif

	// Start worker threads accordingly to previous scan.
	for (auto& work : this->mWorkerFileOrder)
	{
		work.FinishedWork = false;
		this->mThreadPool & THISBACK2(NextScanWorker<T>, &work, ((T)(reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->ScanValue));
	}
}

// Writes a byte array with specified size to the specified address.
template <>
void MemoryScanner::Poke(const SIZE_T address, const ArrayOfBytes& value)
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value.Data, value.Size, NULL);
}

// Writes a unicode string with specified size to the specified address.
template <>
void MemoryScanner::Poke(const SIZE_T address, const WString& value)
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value.Begin(), value.GetLength() * sizeof(wchar), NULL);
}

// Writes an ANSI string with specified size to the specified address.
template <>
void MemoryScanner::Poke(const SIZE_T address, const String& value)
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value.Begin(), value.GetLength(), NULL);
}

// Writes a T value with sizeof(T) size to the specified address.
template <typename T>
void MemoryScanner::Poke(const SIZE_T address, const T& value)
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, &value, sizeof(T), NULL);
}

// Reads a byte array with specified size from the specified address.
template <>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, ArrayOfBytes* outBuffer) const
{
	outBuffer->Allocate(size);
	SIZE_T bytesRead;
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, outBuffer->Data, size, &bytesRead);
	return bytesRead == size;
}

// Reads a unicode string with specified size from the specified address.
template <>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, WString* outBuffer) const
{
	const unsigned int bytesSize = size * sizeof(wchar);
	SIZE_T bytesRead;
	WStringBuffer buffer(size);
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, buffer.Begin(), bytesSize, &bytesRead);
	buffer.Strlen();
	*outBuffer = buffer;
	return bytesRead == bytesSize;
}

// Reads an ANSI string with specified size from the specified address.
template <>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, String* outBuffer) const
{
	SIZE_T bytesRead;
	StringBuffer buffer(size);
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, buffer.Begin(), size, &bytesRead);
	buffer.Strlen();
	*outBuffer = buffer;
	return bytesRead == size;
}

// Reads T value with sizeof(T) size from the specified address.
template <typename T>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, T* outBuffer) const
{
	SIZE_T bytesRead;
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, outBuffer, sizeof(T), &bytesRead);
	return bytesRead == sizeof(T);
}

// ---------------------------------------------------------------------------------------------

// template implementations for linkage errors.
template void MemoryScanner::FirstScan<Byte>();
template void MemoryScanner::FirstScan<short>();
template void MemoryScanner::FirstScan<int>();
template void MemoryScanner::FirstScan<__int64>();
template void MemoryScanner::FirstScan<float>();
template void MemoryScanner::FirstScan<double>();
template void MemoryScanner::FirstScan<String>();
template void MemoryScanner::FirstScan<WString>();
template void MemoryScanner::FirstScan<ArrayOfBytes>();

template void MemoryScanner::NextScan<Byte>();
template void MemoryScanner::NextScan<short>();
template void MemoryScanner::NextScan<int>();
template void MemoryScanner::NextScan<__int64>();
template void MemoryScanner::NextScan<float>();
template void MemoryScanner::NextScan<double>();
template void MemoryScanner::NextScan<String>();
template void MemoryScanner::NextScan<WString>();
template void MemoryScanner::NextScan<ArrayOfBytes>();

template void MemoryScanner::Poke<Byte>(const SIZE_T address, const Byte& value);
template void MemoryScanner::Poke<short>(const SIZE_T address, const short& value);
template void MemoryScanner::Poke<int>(const SIZE_T address, const int& value);
template void MemoryScanner::Poke<__int64>(const SIZE_T address, const __int64& value);
template void MemoryScanner::Poke<float>(const SIZE_T address, const float& value);
template void MemoryScanner::Poke<double>(const SIZE_T address, const double& value);

template bool MemoryScanner::Peek<Byte>(const SIZE_T address, const unsigned int size, Byte* outBuffer) const;
template bool MemoryScanner::Peek<short>(const SIZE_T address, const unsigned int size, short* outBuffer) const;
template bool MemoryScanner::Peek<int>(const SIZE_T address, const unsigned int size, int* outBuffer) const;
template bool MemoryScanner::Peek<__int64>(const SIZE_T address, const unsigned int size, __int64* outBuffer) const;
template bool MemoryScanner::Peek<float>(const SIZE_T address, const unsigned int size, float* outBuffer) const;
template bool MemoryScanner::Peek<double>(const SIZE_T address, const unsigned int size, double* outBuffer) const;