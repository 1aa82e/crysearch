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

// MemoryScanner class default constructor.
MemoryScanner::MemoryScanner()
{
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
	const int opr = SettingsFile::GetInstance()->GetOpenProcessRoutine();
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

// ---------------------------------------------------------------------------------------------

// Worker function that implements specialized behavior for byte-array types.
template <>
void MemoryScanner::FirstScanWorker(MemoryScannerWorkerContext* const context, const ArrayOfBytes& value, CompareFunctionType<ArrayOfBytes> cmp)
{
	unsigned int fileIndex = 0;
	const Byte* const inputData = value.Data;
	const int inputLength = value.Size;
	const unsigned int forLoopLength = context->RegionData.OriginalStartIndex + context->RegionData.Length;
	bool* const localAddresses = context->LocalAddressesBuffer;
	const SIZE_T maxLocalBufferSize = MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];

	// Loop the memory pages for this worker.
	for (unsigned int i = context->RegionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, 1, fileIndex);
		
		// Try to read the memory page contents into local memory.
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;

			// Iterate the current memory page until everything is parsed, but keep the maximum
			// size of the local buffer into account.
			SIZE_T blockIterator = 0;
			while (blockIterator < bytesRead)
			{
				// Iterate through the correctly copied memory page contents.
				const SIZE_T iterationCount = min(bytesRead - blockIterator, maxLocalBufferSize);
				for (SIZE_T j = 0; j < iterationCount; ++j)
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
				}
				
				blockIterator += iterationCount;
				
				// Check if there are actual value results. If there are no, this block can be discarded.
				if (valueIndex > 0)
				{
					// Check whether we have to cache some more search results in the user interface.
					AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, NULL);
					
					// Write storage block header to file.
					storage.AddressCount = addrIndex;
					storage.ValueCount = valueIndex;
					storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
					context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
					
					// Write memory buffers out to file.
					context->OutAddressesFile.Put(localAddresses, addrIndex);

					// Increment block count and increase UI result counter.
					++context->OutAddressesFileHeader.BlockCount;
					this->mScanResultCount += valueIndex;
				}
				
				// Reset indices and start a new block.
				addrIndex = 0;
				valueIndex = 0;
				localBaseAddr += blockIterator;
				storage.BaseAddress = localBaseAddr;
				storage.ValueStorageIndex = fileIndex;
			}
		}
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}

	delete[] buffer;

	// Call the worker epilogue.
	this->FirstWorkerEpilogue(context);
}

// Worker function that implements specialized behavior for Unicode string types.
template <>
void MemoryScanner::FirstScanWorker(MemoryScannerWorkerContext* const context, const WString& value, CompareFunctionType<WString> cmp)
{
	unsigned int fileIndex = 0;
	const wchar* const inputData = value.Begin();
	const int inputLength = value.GetLength();
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;
	const unsigned int forLoopLength = context->RegionData.OriginalStartIndex + context->RegionData.Length;
	bool* const localAddresses = context->LocalAddressesBuffer;
	Byte* const stringLengthsArray = (Byte*)context->LocalValuesBuffer;
	const SIZE_T maxLocalBufferSize = MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];

	// Loop the memory pages for this worker.
	for (unsigned int i = context->RegionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
				
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, 1, fileIndex);
		
		// Try to read the memory page contents into local memory.
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;
			
			// Iterate the current memory page until everything is parsed, but keep the maximum
			// size of the local buffer into account.
			SIZE_T blockIterator = 0;
			while (blockIterator < bytesRead)
			{
				// Iterate through the correctly copied memory page contents.
				const SIZE_T iterationCount = min(bytesRead - blockIterator, maxLocalBufferSize);
				for (SIZE_T j = 0; j < iterationCount; ++j)
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
				}
				
				blockIterator += iterationCount;
				
				// Check if there are actual value results. If there are no, this block can be discarded.
				if (valueIndex > 0)
				{
					// Check whether we have to cache some more search results in the user interface.
					AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengthsArray);
					
					// Write storage block header to file.
					storage.AddressCount = addrIndex;
					storage.ValueCount = valueIndex;
					storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
					context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
					
					// Write memory buffers out to file.
					context->OutAddressesFile.Put(localAddresses, addrIndex);

					// Increment block count and increase UI result counter.
					++context->OutAddressesFileHeader.BlockCount;
					this->mScanResultCount += valueIndex;
				}
				
				// Reset indices and start a new block.
				addrIndex = 0;
				valueIndex = 0;
				localBaseAddr += blockIterator;
				storage.BaseAddress = localBaseAddr;
				storage.ValueStorageIndex = fileIndex;
			}
		}
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	delete[] buffer;

	// Call the worker epilogue.
	this->FirstWorkerEpilogue(context);
}

// Worker function that implements specialized behavior for ANSI string types.
template <>
void MemoryScanner::FirstScanWorker(MemoryScannerWorkerContext* const context, const String& value, CompareFunctionType<String> cmp)
{
	unsigned int fileIndex = 0;
	const char* const inputData = value.Begin();
	const int inputLength = value.GetLength();
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;
	const unsigned int forLoopLength = context->RegionData.OriginalStartIndex + context->RegionData.Length;
	bool* const localAddresses = context->LocalAddressesBuffer;
	Byte* const stringLengthsArray = (Byte*)context->LocalValuesBuffer;
	const SIZE_T maxLocalBufferSize = MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];
	
	// Loop the memory pages for this worker.
	for (unsigned int i = context->RegionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
				
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, 1, fileIndex);
		
		// Try to read the memory page contents into local memory.
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;

			// Iterate the current memory page until everything is parsed, but keep the maximum
			// size of the local buffer into account.
			SIZE_T blockIterator = 0;
			while (blockIterator < bytesRead)
			{
				// Iterate through the correctly copied memory page contents.
				const SIZE_T iterationCount = min(bytesRead - blockIterator, maxLocalBufferSize);
				for (SIZE_T j = 0; j < iterationCount; ++j)
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
				}
				
				blockIterator += iterationCount;
				
				// Check if there are actual value results. If there are no, this block can be discarded.
				if (valueIndex > 0)
				{
					// Check whether we have to cache some more search results in the user interface.
					AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengthsArray);
					
					// Write storage block header to file.
					storage.AddressCount = addrIndex;
					storage.ValueCount = valueIndex;
					storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
					context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
					
					// Write memory buffers out to file.
					context->OutAddressesFile.Put(localAddresses, addrIndex);

					// Increment block count and increase UI result counter.
					++context->OutAddressesFileHeader.BlockCount;
					this->mScanResultCount += valueIndex;
				}
				
				// Reset indices and start a new block.
				addrIndex = 0;
				valueIndex = 0;
				localBaseAddr += blockIterator;
				storage.BaseAddress = localBaseAddr;
				storage.ValueStorageIndex = fileIndex;
			}
		}
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}

	delete[] buffer;

	// Call the worker epilogue.
	this->FirstWorkerEpilogue(context);
}

// Represents the default template worker function for the set of workers including specialized ones.
// This set of workers run the first scan sequence.
template <typename T>
void MemoryScanner::FirstScanWorker(MemoryScannerWorkerContext* const context, const T& value, CompareFunctionType<T> cmp)
{
	unsigned int fileIndex = 0;
	const int fastScanAlignSize = context->FastScanAlignSize;
	const unsigned int forLoopLength = context->RegionData.OriginalStartIndex + context->RegionData.Length;
	bool* const localAddresses = context->LocalAddressesBuffer;
	T* const localValues = (T*)context->LocalValuesBuffer;
	const SIZE_T maxLocalBufferSize = MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD;
	
	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];
	
	// Loop the memory pages for this worker.
	for (unsigned int i = context->RegionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		const MemoryRegion& currentRegion = this->memRegions[i];
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Create a storage structure for this memory page.
		MemoryRegionFileHeader storage(i, currentRegion.BaseAddress, fastScanAlignSize, fileIndex);
		
		// Try to read the memory page contents into local memory.
		SIZE_T bytesRead = 0;
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, &bytesRead))
		{
			SIZE_T localBaseAddr = currentRegion.BaseAddress;
			
			// Iterate the current memory page until everything is parsed, but keep the maximum
			// size of the local buffer into account.
			SIZE_T blockIterator = 0;
			while (blockIterator < bytesRead)
			{
				// Iterate through the correctly copied memory page contents.
				const SIZE_T iterationCount = min(bytesRead - blockIterator, maxLocalBufferSize);
				for (SIZE_T j = 0; j < iterationCount; j += fastScanAlignSize)
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
				}
				
				blockIterator += iterationCount;
				
				// Check if there are actual value results. If there are no, this block can be discarded.
				if (valueIndex > 0)
				{
					// Check whether we have to cache some more search results in the user interface.
					AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, fastScanAlignSize, localAddresses, NULL);
					
					// Write storage block header to file.
					storage.AddressCount = addrIndex;
					storage.ValueCount = valueIndex;
					storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
					context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
					
					// Write memory buffers out to file.
					context->OutAddressesFile.Put(localAddresses, addrIndex);
					context->OutValuesFile.Put(localValues, valueIndex * sizeof(T));

					// Increment block count and increase UI result counter.
					++context->OutAddressesFileHeader.BlockCount;
					this->mScanResultCount += valueIndex;
				}
				
				// Reset indices and start a new block.
				addrIndex = 0;
				valueIndex = 0;
				localBaseAddr += blockIterator;
				storage.BaseAddress = localBaseAddr;
				storage.ValueStorageIndex = fileIndex;
			}
		}
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	delete[] buffer;
	
	// Call the worker epilogue.
	this->FirstWorkerEpilogue(context);
}

// Initializes the first scan sequence. Call this function from the user interface.
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
			&& ((SettingsFile::GetInstance()->GetScanMemPrivate() & (block.Type == MEM_PRIVATE))
			|| (SettingsFile::GetInstance()->GetScanMemImage() & (block.Type == MEM_IMAGE))
			|| (SettingsFile::GetInstance()->GetScanMemMapped() & (block.Type == MEM_MAPPED))))
	    {
	        // Check protection constants to see whether the region should be scanned or not.
	        if ((SettingsFile::GetInstance()->GetScanWritableMemory() & ((block.Protect & MEM_WRITABLE) != 0))
	        	|| (SettingsFile::GetInstance()->GetScanExecutableMemory() & ((block.Protect & MEM_EXECUTABLE) != 0))
	        	|| (SettingsFile::GetInstance()->GetScanCopyOnWriteMemory() & ((block.Protect & MEM_COPYONWRITE) != 0)))
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
	this->mThreadPool.SetThreadPriority(SettingsFile::GetInstance()->GetScanThreadPriority());
#endif

	// Signal user interface with a count to set progress indicator to ready state.
	const int regionCount = this->memRegions.GetCount();
	this->ScanStarted(regionCount);
	
	const SIZE_T workerAmount = totalMemorySize / threadCount;
	int regionIndex = 0;
	int oldRegionIndex = 0;
	
	// Walk the memory pages list and divide the operable memory as efficiently as possible.
	for (int i = 0; i < threadCount;)
	{
		SIZE_T memoryCounter = 0;
		SIZE_T maxPageSize = 0;

		while (memoryCounter < workerAmount && regionIndex < regionCount)
		{
			const MemoryRegion& curReg = memRegions[regionIndex++];
			maxPageSize = max(maxPageSize, curReg.MemorySize);
			memoryCounter += curReg.MemorySize;
		}
		
		MemoryScannerWorkerContext& context = this->mWorkerFileOrder.Add();
		context.WorkerIdentifier = ++i;
		context.MaximumMemoryRegionBufferSize = maxPageSize;
		context.RegionData.OriginalStartIndex = oldRegionIndex;
		context.RegionData.Length = regionIndex - oldRegionIndex;
		
		oldRegionIndex = regionIndex;
	}
	
	// If there is a remainder, add it to the last worker.
	const int remainder = regionCount - oldRegionIndex;
	if (remainder)
	{
		this->mWorkerFileOrder[this->mWorkerFileOrder.GetCount() - 1].RegionData.Length += remainder;
	}
	
	// Fire off the workers.
	for (auto& work : this->mWorkerFileOrder)
	{
		this->mThreadPool & THISBACK1(FirstWorkerPrologue, &work);
	}
}

// This function contains specialized behavior for byte-array types.
template <>
void MemoryScanner::NextScanWorker(MemoryScannerWorkerContext* const context, const ArrayOfBytes& value, CompareFunctionType<ArrayOfBytes> cmp)
{
	unsigned int fileIndex = 0;
	bool* const localAddresses = context->LocalAddressesBuffer;
	const unsigned int blockCount = context->InOldFileHeader.BlockCount;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];

	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		context->InOldAddressesFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		context->InOldAddressesFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
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
						context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						context->OutAddressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++context->OutAddressesFileHeader.BlockCount;
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
				context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				context->OutAddressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++context->OutAddressesFileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}

	delete[] buffer;
	
	// Call the worker epilogue.
	this->NextWorkerEpilogue(context);
}

// This function contains specialized behavior for Unicode string types.
template <>
void MemoryScanner::NextScanWorker(MemoryScannerWorkerContext* const context, const WString& value, CompareFunctionType<WString> cmp)
{
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* const localAddresses = context->LocalAddressesBuffer;
	Byte* const stringLengthsArray = (Byte*)context->LocalValuesBuffer;
	const unsigned int blockCount = context->InOldFileHeader.BlockCount;
	const int inputLengthInChars = value.GetLength();
	const int inputLength = value.GetLength();
	unsigned int fileIndex = 0;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];

	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		context->InOldAddressesFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		context->InOldAddressesFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
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
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengthsArray);
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						context->OutAddressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++context->OutAddressesFileHeader.BlockCount;
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
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengthsArray);
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				context->OutAddressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++context->OutAddressesFileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}

	delete[] buffer;

	// Call the worker epilogue.
	this->NextWorkerEpilogue(context);
}

// This function contains specialized behavior for ANSI string types.
template <>
void MemoryScanner::NextScanWorker(MemoryScannerWorkerContext* const context, const String& value, CompareFunctionType<String> cmp)
{
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* const localAddresses = context->LocalAddressesBuffer;
	Byte* const stringLengthsArray = (Byte*)context->LocalValuesBuffer;
	const int inputLength = value.GetLength();
	unsigned int fileIndex = 0;
	const unsigned int blockCount = context->InOldFileHeader.BlockCount;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];

	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		context->InOldAddressesFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		context->InOldAddressesFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
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
						AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengthsArray);
						
						// Write storage block header to file.
						storage.AddressCount = addrIndex;
						storage.ValueCount = valueIndex;
						storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
						context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						context->OutAddressesFile.Put(localAddresses, addrIndex);

						// Increment block count and increase UI result counter.
						++context->OutAddressesFileHeader.BlockCount;
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
				AddResultsToCacheConditional(addrIndex, valueIndex, localBaseAddr, 1, localAddresses, stringLengthsArray);
				
				// Write storage block header to file.
				storage.AddressCount = addrIndex;
				storage.ValueCount = valueIndex;
				storage.SizeInBytes = sizeof(MemoryRegionFileHeader) + addrIndex;
				context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				context->OutAddressesFile.Put(localAddresses, addrIndex);
				
				// Increment block count and increase UI result counter.
				++context->OutAddressesFileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	delete[] buffer;

	// Call the worker epilogue.
	this->NextWorkerEpilogue(context);
}

// This function is the default template for the set of specialized workers for the next scan.
template <typename T>
void MemoryScanner::NextScanWorker(MemoryScannerWorkerContext* const context, const T& value, CompareFunctionType<T> cmp)
{
	// Create a buffer to store search results in, that can be reused at all times. No need for reallocation anymore.
	bool* const localAddresses = context->LocalAddressesBuffer;
	T* const localValues = (T*)context->LocalValuesBuffer;
	unsigned int fileIndex = 0;
	const unsigned int blockCount = context->InOldFileHeader.BlockCount;

	// Allocate a buffer once, of the size of the biggest memory region to be scanned.
	Byte* const buffer = new Byte[context->MaximumMemoryRegionBufferSize];

	// Walk the blocks in the results file.
	for (unsigned int i = 0; i < blockCount; ++i)
	{
		// Read next block header and data into local buffer.
		MemoryRegionFileHeader block;
		context->InOldAddressesFile.Get(&block, sizeof(MemoryRegionFileHeader));
		bool* oldAddrFileBuffer = new bool[block.AddressCount];
		context->InOldAddressesFile.Get(oldAddrFileBuffer, block.AddressCount);
		
		unsigned int addrIndex = 0;
		unsigned int valueIndex = 0;
		
		// Get the associated memory page.
		const MemoryRegion& currentRegion = this->memRegions[block.PageIndex];
		
		// Try to read the memory page contents into local memory.
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
				context->InOldValuesFile.Seek(block.ValueStorageIndex * sizeof(T));
				context->InOldValuesFile.Get(valuesFileBuffer, block.ValueCount * sizeof(T));
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
						context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
						
						// Write memory buffers out to file.
						context->OutAddressesFile.Put(localAddresses, addrIndex);
						context->OutValuesFile.Put(localValues, valueIndex * sizeof(T));

						// Increment block count and increase UI result counter.
						++context->OutAddressesFileHeader.BlockCount;
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
				context->OutAddressesFile.Put(&storage, sizeof(MemoryRegionFileHeader));
				
				// Write memory buffers out to file.
				context->OutAddressesFile.Put(localAddresses, addrIndex);
				context->OutValuesFile.Put(localValues, valueIndex * sizeof(T));
				
				// Increment block count and increase UI result counter.
				++context->OutAddressesFileHeader.BlockCount;
				this->mScanResultCount += valueIndex;
			}
		}
		
		// Free buffers used for this block.
		delete[] oldAddrFileBuffer;
		
		// Update counters and user interface components.
		this->UpdateScanningProgress(++this->mRegionFinishCount);
	}
	
	delete[] buffer;

	// Call the worker epilogue.
	this->NextWorkerEpilogue(context);
}

// Initializes the next scan sequence. Call this function from the user interface.
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
	this->mThreadPool.SetThreadPriority(SettingsFile::GetInstance()->GetScanThreadPriority());
#endif

	// Start worker threads accordingly to previous scan.
	for (auto& work : this->mWorkerFileOrder)
	{
		this->mThreadPool & THISBACK1(NextWorkerPrologue, &work);
	}
}

// Gets the correct compare function for the upcoming scan.
template <typename T>
CompareFunctionType<T> MemoryScanner::GetCompareFunction()
{
	switch (GlobalScanParameter->GlobalScanType)
	{
		case SCANTYPE_UNKNOWN_INITIAL_VALUE:
			return CompareUnknownInitialValue;
		case SCANTYPE_EXACTVALUE:
		case SCANTYPE_CHANGED:
		case SCANTYPE_UNCHANGED:
			return CompareEqual;
		case SCANTYPE_SMALLERTHAN:
		case SCANTYPE_DECREASED:
			return CompareSmaller;
		case SCANTYPE_GREATERTHAN:
		case SCANTYPE_INCREASED:
			return CompareGreater;
		case SCANTYPE_VALUE_IN_BETWEEN:
			return CompareInBetween;
		default:
			return NULL;
	}
}

// The first scan worker prologue function, which sets up the context for a worker and initiates the scanning phase.
void MemoryScanner::FirstWorkerPrologue(MemoryScannerWorkerContext* const context)
{
	// Set the correct worker corresponding to the value type.
	const MemoryScanValueType tmpType = GlobalScanParameter->GlobalScanValueType;

	// Create address output file in the context, values file is only needed in some situations.
	context->OpenAddresses(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", context->WorkerIdentifier)));
	
	// Create file header for the output file and flush it. This way we already reserve space for it.
	context->OutAddressesFileHeader.WorkerId = context->WorkerIdentifier;
	context->OutAddressesFile.Put(&context->OutAddressesFileHeader, sizeof(StorageFileHeader));
	
	// Allocate local buffer for search result addresses.
	context->AllocateLocalAddressBuffer();
	
	// Select the scanning phase corresponding to the specified data type.
	if (tmpType == VALUETYPE_BYTE)
	{
		context->FastScanAlignSize = 1;
		context->LocalValuesBuffer = new Byte[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		CompareFunctionType<Byte> cmpFunc = this->GetCompareFunction<Byte>();
		this->FirstScanWorker<Byte>(context, ((Byte)(reinterpret_cast<ScanParameters<Byte>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_2BYTE)
	{
		context->FastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(short) : 1;
		context->LocalValuesBuffer = new short[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		CompareFunctionType<short> cmpFunc = this->GetCompareFunction<short>();
		this->FirstScanWorker<short>(context, ((short)(reinterpret_cast<ScanParameters<short>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_4BYTE)
	{
		context->FastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(int) : 1;
		context->LocalValuesBuffer = new int[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		CompareFunctionType<int> cmpFunc = this->GetCompareFunction<int>();
		this->FirstScanWorker<int>(context, ((int)(reinterpret_cast<ScanParameters<int>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_8BYTE)
	{
		context->FastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(int) : 1;
		context->LocalValuesBuffer = new __int64[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		CompareFunctionType<__int64> cmpFunc = this->GetCompareFunction<__int64>();
		this->FirstScanWorker<__int64>(context, ((__int64)(reinterpret_cast<ScanParameters<__int64>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_FLOAT)
	{
		context->FastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(float) : 1;
		context->LocalValuesBuffer = new float[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		CompareFunctionType<float> cmpFunc = this->GetCompareFunction<float>();
		this->FirstScanWorker<float>(context, ((float)(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_DOUBLE)
	{
		context->FastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(int) : 1;
		context->LocalValuesBuffer = new double[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		CompareFunctionType<double> cmpFunc = this->GetCompareFunction<double>();
		this->FirstScanWorker<double>(context, ((double)(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_STRING)
	{
		context->FastScanAlignSize = 1;
		context->LocalValuesBuffer = new Byte[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<String> cmpFunc = this->GetCompareFunction<String>();
		this->FirstScanWorker<String>(context, ((String)(reinterpret_cast<ScanParameters<String>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_WSTRING)
	{
		context->FastScanAlignSize = 1;
		context->LocalValuesBuffer = new Byte[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<WString> cmpFunc = this->GetCompareFunction<WString>();
		this->FirstScanWorker<WString>(context, ((WString)(reinterpret_cast<ScanParameters<WString>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_AOB)
	{
		context->FastScanAlignSize = 1;
		CompareFunctionType<ArrayOfBytes> cmpFunc = this->GetCompareFunction<ArrayOfBytes>();
		this->FirstScanWorker<ArrayOfBytes>(context, ((ArrayOfBytes)(reinterpret_cast<ScanParameters<ArrayOfBytes>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
}

// The next scan worker prologue function, which sets up the context for a worker and initiates the scanning phase.
void MemoryScanner::NextWorkerPrologue(MemoryScannerWorkerContext* const context)
{
	// Set the finished work flag to false.
	context->FinishedWork = false;
	
	// Set the correct worker corresponding to the value type.
	const MemoryScanValueType tmpType = GlobalScanParameter->GlobalScanValueType;
	
	// Create address output file in the context, values file is only needed in some situations.
	context->OpenAddresses(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", context->WorkerIdentifier)));
	
	// Create file header for the output file and flush it. This way we already reserve space for it.
	context->OutAddressesFileHeader.BlockCount = 0;
	context->OutAddressesFile.Put(&context->OutAddressesFileHeader, sizeof(StorageFileHeader));

	// Allocate local buffer for search result addresses.
	context->AllocateLocalAddressBuffer();
	
	// Open the existing search results files.
	context->OpenInputAddresses(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", context->WorkerIdentifier)));
	context->InOldAddressesFile.Get(&context->InOldFileHeader, sizeof(StorageFileHeader));
	
	if (GlobalScanParameter->GlobalScanType >= SCANTYPE_CHANGED)
	{
		context->OpenInputValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.tempSCANNING", context->WorkerIdentifier)));
	}

	// Select the scanning phase corresponding to the specified data type.
	if (tmpType == VALUETYPE_BYTE)
	{
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		context->LocalValuesBuffer = new Byte[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<Byte> cmpFunc = this->GetCompareFunction<Byte>();
		this->NextScanWorker<Byte>(context, ((Byte)(reinterpret_cast<ScanParameters<Byte>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_2BYTE)
	{
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		context->LocalValuesBuffer = new short[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<short> cmpFunc = this->GetCompareFunction<short>();
		this->NextScanWorker<short>(context, ((short)(reinterpret_cast<ScanParameters<short>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_4BYTE)
	{
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		context->LocalValuesBuffer = new int[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<int> cmpFunc = this->GetCompareFunction<int>();
		this->NextScanWorker<int>(context, ((int)(reinterpret_cast<ScanParameters<int>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_8BYTE)
	{
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		context->LocalValuesBuffer = new __int64[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<__int64> cmpFunc = this->GetCompareFunction<__int64>();
		this->NextScanWorker<__int64>(context, ((__int64)(reinterpret_cast<ScanParameters<__int64>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_FLOAT)
	{
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		context->LocalValuesBuffer = new float[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<float> cmpFunc = this->GetCompareFunction<float>();
		this->NextScanWorker<float>(context, ((float)(reinterpret_cast<ScanParameters<float>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_DOUBLE)
	{
		context->OpenValues(AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", context->WorkerIdentifier)));
		context->LocalValuesBuffer = new double[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<double> cmpFunc = this->GetCompareFunction<double>();
		this->NextScanWorker<double>(context, ((double)(reinterpret_cast<ScanParameters<double>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_STRING)
	{
		context->LocalValuesBuffer = new Byte[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<String> cmpFunc = this->GetCompareFunction<String>();
		this->NextScanWorker<String>(context, ((String)(reinterpret_cast<ScanParameters<String>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_WSTRING)
	{
		context->LocalValuesBuffer = new Byte[MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD];
		CompareFunctionType<WString> cmpFunc = this->GetCompareFunction<WString>();
		this->NextScanWorker<WString>(context, ((WString)(reinterpret_cast<ScanParameters<WString>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
	else if (tmpType == VALUETYPE_AOB)
	{
		CompareFunctionType<ArrayOfBytes> cmpFunc = this->GetCompareFunction<ArrayOfBytes>();
		this->NextScanWorker<ArrayOfBytes>(context, ((ArrayOfBytes)(reinterpret_cast<ScanParameters<ArrayOfBytes>*>(GlobalScanParameter))->ScanValue), cmpFunc);
	}
}

// The first scan worker epilogue, which releases resources and finalizes the scan.
void MemoryScanner::FirstWorkerEpilogue(MemoryScannerWorkerContext* const context)
{
	// Seek back to the begin of the file to overwrite the file header with new information.
	context->OutAddressesFile.Seek(0);
	context->OutAddressesFile.Put(&context->OutAddressesFileHeader, sizeof(StorageFileHeader));

	// Release local addresses buffer.
	context->ReleaseLocalBuffers();

	// Close output files in the context.
	context->ReleaseFiles();
	
	// Indicate that this worker is done processing.
	context->FinishedWork = true;
}

// The next scan worker epilogue, which releases resources and finalizes the scan.
void MemoryScanner::NextWorkerEpilogue(MemoryScannerWorkerContext* const context)
{
	// Seek back to the begin of the file to overwrite the file header with new information.
	context->OutAddressesFile.Seek(0);
	context->OutAddressesFile.Put(&context->OutAddressesFileHeader, sizeof(StorageFileHeader));
	
	// Release local addresses buffer.
	context->ReleaseLocalBuffers();
	
	// Close output files in the context.
	context->ReleaseFiles();
	
	// Delete the old input files.
	FileDelete(context->InOldAddressesFilePath);
	FileDelete(context->InOldValuesFilePath);
	
	// Indicate that this worker is done processing.
	context->FinishedWork = true;
}