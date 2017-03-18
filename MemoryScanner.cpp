#include "MemoryScanner.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"
#include "MemoryScannerIO.h"

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

// Walks a boolean buffer until it finds a 1 (true).
inline const bool* RunForOne(const bool* AddressBuffer, const int maxCount)
{
	const bool* iterator = AddressBuffer;
	const bool* const endIterator = iterator + maxCount;
	while (!*iterator && iterator < endIterator)
	{
		++iterator;
	}
	
	return iterator;
}

// Adds a set of new search results to the cache vectors. Up to a million results are kept in memory for GUI visibility.
void AddResultsToCache(const int addrCount, const int valueCount, const SIZE_T baseAddr, const unsigned int distance, const bool* AddressBuffer, const Byte* lengthBuffers)
{
	// Lock access to the cache vector.
	CacheMutex.Enter();

	// While the count is not yet bigger than the threshold, we may copy the entries into the cache.
	const int possible = MEMORYSCANNER_CACHE_LIMIT - CachedAddresses.GetCount();
	if (possible > 0)
	{
		// Linearly iterating the module list to find contained addresses is rather expensive.
		// We can make the assumption on the input data that the number of resulting modules is small.
		// Therefore, caching the lookup result for more addresses is a good solution.
		const Win32ModuleInformation* mCachedContainedMod = NULL;
		SIZE_T cachedEndAddr = 0;
		
		// Add entries to the cache.
		const bool* runBuf = AddressBuffer;
		const int minIt = min(possible, valueCount);
		for (int i = 0; i < minIt; ++i)
		{
			// Find the next address that needs to be cached and calculate the actual address location.
			runBuf = RunForOne(runBuf, addrCount);
			const SIZE_T actualAddr = baseAddr + (runBuf++ - AddressBuffer) * distance;
			
			// Do we need to find the next module or is this address still in the current module?
			if (!mCachedContainedMod || (actualAddr < mCachedContainedMod->BaseAddress || actualAddr > cachedEndAddr))
			{
				// Find out whether this address points inside a loaded module.
				mCachedContainedMod = mModuleManager->GetModuleFromContainedAddress(actualAddr);
				cachedEndAddr = mCachedContainedMod ? (mCachedContainedMod->BaseAddress + mCachedContainedMod->Length) : 0;
			}
			
			// Add the cache values to the appropriate buffer.
			SearchResultCacheEntry& entry = CachedAddresses.Add(SearchResultCacheEntry(actualAddr, !!mCachedContainedMod));

			// If the string length is specified, add it to the search result identifier.
			if (lengthBuffers)
			{
				entry.StringLength = lengthBuffers[i];
			}
		}
	}

	// Release the lock.
	CacheMutex.Leave();
}

// Adds a set of new search results to the cache vectors after checking for availability.
void AddResultsToCacheConditional(const int addrCount, const int valueCount, const SIZE_T baseAddr, const unsigned int distance, const bool* AddressBuffer, const Byte* lengthBuffers)
{
	// Check whether the UI cache vectors have room available.
	if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
	{
		// There is room, add entries to the cache.
		AddResultsToCache(addrCount, valueCount, baseAddr, distance, AddressBuffer, lengthBuffers);
	}
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareGreater(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareGreater(const float& input, const float& expected)
{
	return ((int)input > (int)expected);
}

template <>
const bool CompareGreater(const double& input, const double& expected)
{
	return ((int)input > (int)expected);
}

template <typename T>
const bool CompareGreater(const T& input, const T& expected)
{
	return (input > expected);
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareSmaller(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareSmaller(const float& input, const float& expected)
{
	return ((int)input < (int)expected);
}

template <>
const bool CompareSmaller(const double& input, const double& expected)
{
	return ((int)input < (int)expected);
}

template <typename T>
const bool CompareSmaller(const T& input, const T& expected)
{
	return (input < expected);
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareEqual(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareEqual(const float& input, const float& expected)
{
	return (((int)input) == ((int)expected));
}

template <>
const bool CompareEqual(const double& input, const double& expected)
{
	return (((int)input) == ((int)expected));
}

template <typename T>
const bool CompareEqual(const T& input, const T& expected)
{
	return (input == expected);
}

// ---------------------------------------------------------------------------------------------

template <>
const bool CompareInBetween(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <>
const bool CompareInBetween(const float& input, const float& expected)
{
	return ((int)input >= (int)expected && (int)input <= (int)(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->OuterScanValue);
}

template <>
const bool CompareInBetween(const double& input, const double& expected)
{
	return ((int)input >= (int)expected && (int)input <= (int)(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->OuterScanValue);
}

template <typename T>
const bool CompareInBetween(const T& input, const T& expected)
{
	// Is the input value at least expected and at most the second expected value?
	return (input >= expected && input <= (reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->OuterScanValue);
}

// ---------------------------------------------------------------------------------------------

template <typename T>
const bool CompareUnknownInitialValue(const T& input, const T& expected)
{
	// Unknown initial value should return everything that is found by the scanner.
	return true;
}

// ---------------------------------------------------------------------------------------------

// Compares ANSI and Unicode strings until a null character is found.
const bool CompareStringNullCharA(const char* input, const int inputLength, const char* expected, int* const outputLength)
{
	// Do the initial comparison of the input string.
	if (strncmp(input, expected, inputLength) == 0)
	{
		const char* iterator = input + inputLength;
		const int endIterator = STRING_MAX_UNTIL_NULL - inputLength;
		int i = 0;
		
		// Keep collecting characters until a NULL character is reached.
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

// Compares Unicode strings until a null character is found.
const bool CompareStringNullCharW(const wchar* input, const int inputLength, const wchar* expected, int* const outputLength)
{
	// Do the initial comparison of the input string.
	if (wcsncmp(input, expected, inputLength) == 0)
	{
		const wchar* iterator = input + inputLength;
		const int endIterator = STRING_MAX_UNTIL_NULL - inputLength;
		int i = 0;
		
		// Keep collecting characters until a NULL character is reached.
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
	// Set the scanner to not running.
	this->ScanRunning = false;
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

// Function that assigns the correct compare function using the user selected scan type, and fires of the workers accordingly.
template <typename T>
void MemoryScanner::AssignAndFire(const bool first)
{
	// Assign the workers the correct compare function.
	CompareFunctionType<T> cmpFunc;
	switch (GlobalScanParameter->GlobalScanType)
	{
		case SCANTYPE_UNKNOWN_INITIAL_VALUE:
			cmpFunc = CompareUnknownInitialValue;
			break;
		case SCANTYPE_EXACTVALUE:
			cmpFunc = CompareEqual;
			break;
		case SCANTYPE_SMALLERTHAN:
			cmpFunc = CompareSmaller;
			break;
		case SCANTYPE_GREATERTHAN:
			cmpFunc = CompareGreater;
			break;
		case SCANTYPE_VALUE_IN_BETWEEN:
			cmpFunc = CompareInBetween;
			break;
		case SCANTYPE_CHANGED:
			cmpFunc = CompareEqual;
			break;
		case SCANTYPE_UNCHANGED:
			cmpFunc = CompareEqual;
			break;
		case SCANTYPE_INCREASED:
			cmpFunc = CompareGreater;
			break;
		case SCANTYPE_DECREASED:
			cmpFunc = CompareSmaller;
			break;
		default:
			cmpFunc = NULL;
			break;
	}

	// Start worker threads accordingly to previous scan.
	for (auto& work : this->mWorkerFileOrder)
	{
		work.FinishedWork = false;
		
		// Are we firing a first- or a refreshment scan?
		if (first)
		{
			this->mThreadPool & THISBACK3(FirstScanWorker<T>, &work, ((T)(reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->ScanValue), cmpFunc);
		}
		else
		{
			this->mThreadPool & THISBACK3(NextScanWorker<T>, &work, ((T)(reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->ScanValue), cmpFunc);
		}
	}
}

// Worker function that implements specialized behavior for byte-array types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const ArrayOfBytes& value, CompareFunctionType<ArrayOfBytes> cmp)
{
	// Create output files, the destructor will close them.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	
	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	unsigned int fileIndex = 0;
	const Byte* const inputData = value.Data;
	const int inputLength = value.Size;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, 1, fileIndex);
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;
			
			// Iterate through the correctly copied memory page contents.
			for (SIZE_T j = 0; j < bytesRead; ++j)
			{
				const Byte* tempStore = &(buffer[j]);
				
				// Compare the string at this memory address.
				if (memcmp(tempStore, inputData, inputLength) == 0)
				{
					localAddresses[addrIndex] = true;
					++fileIndex;
					++valueIndex;
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, NULL);
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += j;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, NULL);
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Worker function that implements specialized behavior for Unicode string types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const WString& value, CompareFunctionType<WString> cmp)
{
	// Create output files, the destructor will close them.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	
	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	unsigned int fileIndex = 0;
	const wchar* const inputData = value.Begin();
	const int inputLength = value.GetLength();
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
				
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, 1, fileIndex);
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;
			
			// Iterate through the correctly copied memory page contents.
			for (SIZE_T j = 0; j < bytesRead; ++j)
			{
				const wchar* strPtr = (wchar*)&(buffer[j]);
				
				// Compare the string at this memory address.
				int outputLength = inputLength;
				if (localNullScan ? CompareStringNullCharW(strPtr, inputLength, inputData, &outputLength) : (wcsncmp(strPtr, inputData, inputLength) == 0))
				{
					localAddresses[addrIndex] = true;
					stringLengthsArray[valueIndex++] = outputLength;
					++fileIndex;
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += j;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Worker function that implements specialized behavior for ANSI string types.
template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const String& value, CompareFunctionType<String> cmp)
{
	// Create output files, the destructor will close them.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	
	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	unsigned int fileIndex = 0;
	const char* const inputData = value.Begin();
	const int inputLength = value.GetLength();
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
				
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, 1, fileIndex);
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;
			
			// Iterate through the correctly copied memory page contents.
			for (SIZE_T j = 0; j < bytesRead; ++j)
			{
				const char* strPtr = (char*)&(buffer[j]);
				
				// Compare the string at this memory address.
				int outputLength = inputLength;
				if (localNullScan ? CompareStringNullCharA(strPtr, inputLength, inputData, &outputLength) : (strncmp(strPtr, inputData, inputLength) == 0))
				{
					localAddresses[addrIndex] = true;
					stringLengthsArray[valueIndex++] = outputLength;
					++fileIndex;
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += j;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// Represents the default template worker function for the set of workers including specialized ones.
// This set of workers run the first scan sequence.
template <typename T>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData* const regionData, const T& value, CompareFunctionType<T> cmp)
{
	// Create output files, the destructor will close them.
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileOut valFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData->WorkerIdentifier)));
	
	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Set the correct memory alignment.
	int fastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(T) : 1;
	if (fastScanAlignSize == sizeof(__int64) || fastScanAlignSize == sizeof(double))
	{
		fastScanAlignSize = sizeof(int);
	}
	
	unsigned int fileIndex = 0;
	const unsigned int forLoopLength = regionData->OriginalStartIndex + regionData->Length;
	
	// Create a buffer to store search results in, that can be reused at all times.
	// No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	T* localValues = new T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	
	// Loop the memory pages for this worker.
	for (unsigned int i = regionData->OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
				
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, fastScanAlignSize, fileIndex);
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;
			
			// Iterate through the correctly copied memory page contents.
			for (SIZE_T j = 0; j < bytesRead; j += fastScanAlignSize)
			{
				const T tempStore = *(T*)&(buffer[j]);
				
				// Compare the value at this memory address.
				if (cmp(tempStore, value))
				{
					localAddresses[addrIndex] = true;
					localValues[valueIndex++] = tempStore;
					++fileIndex;
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, fastScanAlignSize, localAddresses, NULL);
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);
						valFile.Put(localValues, valueIndex * sizeof(T));

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += j;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, fastScanAlignSize, localAddresses, NULL);
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				valFile.Put(localValues, valueIndex * sizeof(T));
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		delete[] buffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;
	delete[] localValues;
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
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
	for (int i = 0; i < this->memRegions.GetCount(); ++i)
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
	
	// Fire off the workers.
	this->AssignAndFire<T>(true);
}

// This function contains specialized behavior for byte-array types.
template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const ArrayOfBytes& value, CompareFunctionType<ArrayOfBytes> cmp)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));	
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));

	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));

	FileIn oldAddrFile(addrFileOld);
	
	unsigned int fileIndex = 0;
	
	// Open the existing search results file and check the number of blocks.
	StorageFileHeader oldFh;
	oldAddrFile.Get(&oldFh, sizeof(StorageFileHeader));
	const unsigned int blockCount = oldFh.BlockCount;
	
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	
	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		oldAddrFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		oldAddrFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)block.BaseAddress, buffer, currentRegion.MemorySize - (block.BaseAddress - currentRegion.BaseAddress), NULL))
		{
			// Create a new storage structure for this memory page.
			MemoryRegionFileHeader storage(block.PageIndex, currentRegion.BaseAddress, block.AddressOffsetAlignment, fileIndex);
			
			SIZE_T localBaseAddr = block.BaseAddress;
			
			// Walk through the saved search results.
			for (unsigned int j = 0; j < block.AddressCount; ++j)
			{
				const unsigned int actualOffset = j * block.AddressOffsetAlignment;
				
				// Is this address part of the search results?
				if (oldAddrFileBuffer[j])
				{
					// Get the value at the actual address that was stored.
					const Byte* currentDataPtr = (buffer + actualOffset);
					
					// Comparison result?
					if (memcmp(currentDataPtr, value.Data, value.Size) == 0)
					{						
						localAddresses[addrIndex] = true;
						++fileIndex;
						++valueIndex;
					}
					else
					{
						localAddresses[addrIndex] = false;
					}
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, NULL);
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += actualOffset;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, NULL);
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] buffer;
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// This function contains specialized behavior for Unicode string types.
template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const WString& value, CompareFunctionType<WString> cmp)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));	
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));

	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));

	FileIn oldAddrFile(addrFileOld);
	
	const int inputLengthInChars = value.GetLength();
	const int inputLength = value.GetLength();
	unsigned int fileIndex = 0;
	
	// Open the existing search results file and check the number of blocks.
	StorageFileHeader oldFh;
	oldAddrFile.Get(&oldFh, sizeof(StorageFileHeader));
	const unsigned int blockCount = oldFh.BlockCount;
	
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	
	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		oldAddrFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		oldAddrFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)block.BaseAddress, buffer, currentRegion.MemorySize - (block.BaseAddress - currentRegion.BaseAddress), NULL))
		{
			// Create a new storage structure for this memory page.
			MemoryRegionFileHeader storage(block.PageIndex, currentRegion.BaseAddress, block.AddressOffsetAlignment, fileIndex);
			
			SIZE_T localBaseAddr = block.BaseAddress;
			
			// Walk through the saved search results.
			for (unsigned int j = 0; j < block.AddressCount; ++j)
			{
				const unsigned int actualOffset = j * block.AddressOffsetAlignment;
				
				// Is this address part of the search results?
				if (oldAddrFileBuffer[j])
				{
					// Get the value at the actual address that was stored.
					const wchar* currentDataPtr = (wchar*)(buffer + actualOffset);
					
					// Comparison result?
					if (wcsncmp(currentDataPtr, value, inputLength) == 0)
					{						
						localAddresses[addrIndex] = true;
						stringLengthsArray[valueIndex++] = inputLengthInChars;
						++fileIndex;
					}
					else
					{
						localAddresses[addrIndex] = false;
					}
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += actualOffset;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] buffer;
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// This function contains specialized behavior for ANSI string types.
template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const String& value, CompareFunctionType<String> cmp)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));	
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));

	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));

	FileIn oldAddrFile(addrFileOld);
	
	const int inputLength = value.GetLength();
	unsigned int fileIndex = 0;
	
	// Open the existing search results file and check the number of blocks.
	StorageFileHeader oldFh;
	oldAddrFile.Get(&oldFh, sizeof(StorageFileHeader));
	const unsigned int blockCount = oldFh.BlockCount;
	
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	Vector<Byte> stringLengths;
	stringLengths.Reserve(MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD);
	Byte* const stringLengthsArray = stringLengths.Begin();
	
	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		oldAddrFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		oldAddrFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)block.BaseAddress, buffer, currentRegion.MemorySize - (block.BaseAddress - currentRegion.BaseAddress), NULL))
		{
			// Create a new storage structure for this memory page.
			MemoryRegionFileHeader storage(block.PageIndex, currentRegion.BaseAddress, block.AddressOffsetAlignment, fileIndex);
			
			SIZE_T localBaseAddr = block.BaseAddress;
			
			// Walk through the saved search results.
			for (unsigned int j = 0; j < block.AddressCount; ++j)
			{
				const unsigned int actualOffset = j * block.AddressOffsetAlignment;
				
				// Is this address part of the search results?
				if (oldAddrFileBuffer[j])
				{
					// Get the value at the actual address that was stored.
					const char* currentDataPtr = (char*)(buffer + actualOffset);
					
					// Comparison result?
					if (strncmp(currentDataPtr, value, inputLength) == 0)
					{						
						localAddresses[addrIndex] = true;
						stringLengthsArray[valueIndex++] = inputLength;
						++fileIndex;
					}
					else
					{
						localAddresses[addrIndex] = false;
					}
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += actualOffset;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengths.Begin());
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] buffer;
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
	// Delete allocated array buffers.
	delete[] localAddresses;

	// Delete old temporary files, they have been replaced by new ones.
	FileDelete(addrFileOld);
	
	// Indicate that this worker is done processing.
	regionData->FinishedWork = true;
}

// This function is the default template for the set of specialized workers for the next scan.
template <typename T>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData* const regionData, const T& value, CompareFunctionType<T> cmp)
{
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData->WorkerIdentifier));
	const String valuesFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.tempSCANNING", regionData->WorkerIdentifier));
	
	FileOut addressesFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData->WorkerIdentifier)));
	FileOut valFile(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData->WorkerIdentifier)));

	// Create file header for the output file and flush it. This way we already reserve space for it.
	StorageFileHeader fileHeader(regionData->WorkerIdentifier);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));

	FileIn oldAddrFile(addrFileOld);
	FileIn oldValuesFile;
	
	// This part is crucial for the comparison scan types (CHANGED, UNCHANGED, INCREASED, DECREASED) to work!
	if (GlobalScanParameter->GlobalScanType >= SCANTYPE_CHANGED)
	{
		oldValuesFile.Open(valuesFileOld);
	}
	
	unsigned int fileIndex = 0;
	
	// Open the existing search results file and check the number of blocks.
	StorageFileHeader oldFh;
	oldAddrFile.Get(&oldFh, sizeof(StorageFileHeader));
	const unsigned int blockCount = oldFh.BlockCount;
	
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* localAddresses = new bool[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	T* localValues = new T[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
	
	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		oldAddrFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		oldAddrFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)block.BaseAddress, buffer, currentRegion.MemorySize - (block.BaseAddress - currentRegion.BaseAddress), NULL))
		{
			// Create a new storage structure for this memory page.
			MemoryRegionFileHeader storage(block.PageIndex, currentRegion.BaseAddress, block.AddressOffsetAlignment, fileIndex);
			
			// If the user selected a scan type that requires comparison against saved search results, we need to load the file from disk.
			T* valuesFileBuffer = NULL;
			unsigned int oldTempFileIndex = 0;
			if ((int)GlobalScanParameter->GlobalScanType >= (int)SCANTYPE_CHANGED)
			{
				valuesFileBuffer = new T[block.ValueCount];
				oldValuesFile.Seek(block.ValueStorageIndex * sizeof(T));
				oldValuesFile.Get(valuesFileBuffer, block.ValueCount * sizeof(T));
			}
			
			SIZE_T localBaseAddr = block.BaseAddress;
			
			// Walk through the saved search results.
			for (unsigned int j = 0; j < block.AddressCount; ++j)
			{
				const unsigned int actualOffset = j * block.AddressOffsetAlignment;
				
				// Is this address part of the search results?
				if (oldAddrFileBuffer[j])
				{
					// Get the value at the actual address that was stored.
					const T currentDataPtr = *(T*)(buffer + actualOffset);
					
					// Compare the current and saved values with whatever configured comparetor.
					bool compareSucceeded = false;
					if (GlobalScanParameter->GlobalScanType == SCANTYPE_CHANGED)
					{
						compareSucceeded = !cmp(currentDataPtr, valuesFileBuffer[oldTempFileIndex]);
					}
					else if (GlobalScanParameter->GlobalScanType >= (int)SCANTYPE_UNCHANGED)
					{
						compareSucceeded = cmp(currentDataPtr, valuesFileBuffer[oldTempFileIndex]);
					}
					else
					{
						compareSucceeded = cmp(currentDataPtr, value);
					}
					
					// Whether the comparison succeeded or not, this seperate array index always has to be incremented.
					++oldTempFileIndex;
					
					// Comparison result?
					if (compareSucceeded)
					{						
						localAddresses[addrIndex] = true;
						localValues[valueIndex++] = currentDataPtr;
						++fileIndex;
					}
					else
					{
						localAddresses[addrIndex] = false;
					}
				}
				else
				{
					localAddresses[addrIndex] = false;
				}
				
				++addrIndex;
				
				// Check whether we have reached the bounds of the array, maybe we need to write the array to file.
				if (addrIndex >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
				{
					// Check if there are actual value results. If there are no, this block can be discarded.
					if (valueIndex > 0)
					{
						// Check whether we have to cache some more search results in the user interface.
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, block.AddressOffsetAlignment, localAddresses, NULL);
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						addressesFile.Put(localAddresses, addrIndex);
						valFile.Put(localValues, valueIndex * sizeof(T));

						// Increment block count and increase UI result counter.
						++fileHeader.BlockCount;
						this->mScanResultCount += valueIndex;
					}
					
					// Reset indices and start a new block.
					addrIndex = 0;
					valueIndex = 0;
					localBaseAddr += actualOffset;
					storage.BaseAddress = localBaseAddr;
					storage.ValueStorageIndex = fileIndex;
				}
			}

			// If we allocated a buffer for the saved search values, we need to destroy it.
			if (valuesFileBuffer)
			{
				delete[] valuesFileBuffer;
			}
			
			// If this memory page generated search results, flush these to the output file.
			if (valueIndex > 0)
			{
				// Check whether we have to cache some more search results in the user interface.
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, block.AddressOffsetAlignment, localAddresses, NULL);
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				addressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				addressesFile.Put(localAddresses, addrIndex);
				valFile.Put(localValues, valueIndex * sizeof(T));
				
				// Increment block count and increase UI result counter.
				++fileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] buffer;
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	// If necessary, close the old values file.
	if (oldValuesFile.IsOpen())
	{
		oldValuesFile.Close();
	}
	
	// Close opened input file, we need to delete it.
	oldAddrFile.Close();
	
	// Seek back to the begin of the file to overwrite the file header with new information.
	addressesFile.Seek(0);
	addressesFile.Put(&fileHeader, sizeof(StorageFileHeader));
	
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
	
	// Set thread priority for the workers ran by this scan session.
#ifdef _MULTITHREADED
	this->mThreadPool.SetThreadPriority(this->mSettingsInstance->GetScanThreadPriority());
#endif

	// Start worker threads accordingly to previous scan.
	this->AssignAndFire<T>(false);
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