#include "MemoryScanner.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"

#include <Psapi.h>

// Global synchronisation primitives to avoid unnessecary thread usage and speed up calls.
volatile Atomic RegionFinishCount;

// The memory scanner thread pool and synchronisation primitives.
CoWork threadPool;
StaticMutex CacheMutex;
volatile Atomic threadIncrement = 0;

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
	CacheMutex.Enter();
	
	// While the count is not yet bigger than the threshold, copy the entries into the cache
	const int newCount = CachedAddresses.GetCount() + Resultcount;
	int indexBarrier = 0;

	if (newCount > MEMORYSCANNER_CACHE_LIMIT)
	{
		const int countRemainder = newCount % MEMORYSCANNER_CACHE_LIMIT;
		if ((newCount - countRemainder) == MEMORYSCANNER_CACHE_LIMIT)
		{
			indexBarrier = Resultcount - countRemainder;
		}
	}
	else
	{
		indexBarrier = Resultcount;
	}

	if (indexBarrier > 0)
	{
		const Win32ModuleInformation* mod = mModuleManager->GetModuleFromContainedAddress(AddressBuffer[0]);
		for (int i = 0; i < indexBarrier; ++i)
		{
			// Add the cache values to the appropriate buffer.
			SearchResultCacheEntry& entry = CachedAddresses.Add(SearchResultCacheEntry(AddressBuffer[i], !!mod));
			
			// If the string length is specified, add it to the search result identifier.
			if (lengthBuffers)
			{
				entry.StringLength = lengthBuffers[i];
			}
		}
	}
	
	CacheMutex.Leave();
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
bool MemoryScanner::InitializeExistingProcess(const int processId, const String& exeTitle)
{
	switch (this->mSettingsInstance->GetOpenProcessRoutine())
	{
		case ROUTINE_OPENPROCESS:
			this->mOpenedProcessHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
				| PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, FALSE, processId);
			break;
		case ROUTINE_NTOPENPROCESS:
			CLIENT_ID cid;
			cid.UniqueThread = 0;
			cid.UniqueProcess = (HANDLE)processId;
			
			OBJECT_ATTRIBUTES objAttr;
			InitializeObjectAttributes(&objAttr, NULL, 0, 0, NULL);
		    
		    if (!CrySearchRoutines.NtOpenProcess)
			{
				this->ErrorOccured(NATIVEROUTINEGETPROCFAILED);
				return false;
			}
			
			CrySearchRoutines.NtOpenProcess(&this->mOpenedProcessHandle, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
				| PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, &objAttr, &cid);
			break;
	}
	
	if (!this->mOpenedProcessHandle || this->mOpenedProcessHandle == INVALID_HANDLE_VALUE)
	{
		this->ErrorOccured(OPENPROCESSFAILED);
		return false;
	}
	
	// Process succesfully loaded, set identifiers and return.
	this->mLoadedProcessId = processId;
	this->isX86Process = IsI386Process(this->mOpenedProcessHandle);

	// If a process was opened by dragging the cursor onto another window, the process name is empty from the start.
	if (exeTitle.IsEmpty())
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

// Returns the amount of scan results.
const int MemoryScanner::GetScanResultCount() const
{
	return this->mScanResultCount;
}

// Returns the reference to the internal worker parameter data.
const Vector<WorkerRegionParameterData>& MemoryScanner::QueryWorkerData() const
{
	return this->mWorkerFileOrder;
}

// Compare functions

template <>
bool __fastcall CompareGreater(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	// Dummy function, nessecary for compilation but will never be called.
	return false;
}

template <class T>
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

template <class T>
bool __fastcall CompareSmaller(const T& input, const T& expected)
{
	return (input < expected);
}

template <>
bool __fastcall CompareEqual(const ArrayOfBytes& input, const ArrayOfBytes& expected)
{
	/*const Byte* first = input.Data;
	const Byte* end = input.Data + input.Size;
	const Byte* expectedFirst = expected.Data;
	const Byte* expectedEnd = expected.Data + expected.Size;
	
	while (first != end)
	{
		if (*first++ != *expectedFirst++ || *end-- != *expectedEnd--)
		{
			return false;
		}
	}
	
	return true;*/
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

template <class T>
bool __fastcall CompareEqual(const T& input, const T& expected)
{
	return (input == expected);
}

template <class T>
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

void MemoryScanner::ReallocateMemoryScannerBufferCounter(unsigned int* const length)
{
	if (*length >= MEMORY_SCANNER_BUFFER_LENGTH_THRESHOLD)
	{
		*length = (unsigned int)(*length * MEMORY_SCANNER_BUFFER_REALLOCATION_FACTOR);
	}
	else
	{
		*length *= 2;
	}
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

// Scanning functions

template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData& regionData, const double& value)
{
	const String addrFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	const String valuesFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData.WorkerIdentifier));
	regionData.AddressesFile = CreateFile(addrFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	regionData.ValuesFile = CreateFile(valuesFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	
	int fastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(int) : 1;
	
	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;
	
	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int arrayIndex = 0;
		unsigned int currentArrayLength = 256;
		SIZE_T* localAddresses = NULL;
		double* localValues = NULL;
		MemoryRegion& currentRegion = this->memRegions[i];
		
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < currentRegion.MemorySize; i += fastScanAlignSize)
			{
				const double* tempStore = (double*)&(buffer[i]);
				
				if ((*reinterpret_cast<ValueComparator<double>*>(this->mCompareValues))(*tempStore, value))
				{
					if (!localAddresses || !localValues)
					{
						localAddresses = new SIZE_T[currentArrayLength];
						localValues = new double[currentArrayLength];
					}
					
					if (arrayIndex >= currentArrayLength)
					{
						const unsigned int oldCurrentArrayLength = currentArrayLength;
						this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
						
						SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
						memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
						delete[] localAddresses;
						localAddresses = newAddressesArray;
						
						double* newValuesArray = new double[currentArrayLength];
						memcpy(newValuesArray, localValues, oldCurrentArrayLength * sizeof(double));
						delete[] localValues;
						localValues = newValuesArray;
					}
					
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					localValues[arrayIndex++] = *tempStore;
					
					++fileIndex;
				}
			}
		}
		
		delete[] buffer;
		
		if (arrayIndex > 0)
		{
			AtomicXAdd(this->mScanResultCount, arrayIndex);
			
			if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
			{
				AddResultsToCache(arrayIndex, localAddresses, NULL);
			}
				
			WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
			delete[] localAddresses;
				
			WriteFile(regionData.ValuesFile, localValues, arrayIndex * sizeof(double), &numberOfBytesWritten, NULL);
			delete[] localValues;
		}
		else
		{
			if (localAddresses)
			{
				delete[] localAddresses;
				delete[] localValues;				
			}
		}
		
		currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(regionData.AddressesFile);
	CloseHandle(regionData.ValuesFile);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData& regionData, const ArrayOfBytes& value)
{
	const String addrFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	regionData.AddressesFile = CreateFile(addrFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	
	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;
	
	const Byte* const inputData = value.Data;
	const int inputLength = value.Size;

	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int arrayIndex = 0;
		unsigned int currentArrayLength = 256;
		SIZE_T* localAddresses = NULL;
		MemoryRegion& currentRegion = this->memRegions[i];
		
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < currentRegion.MemorySize; ++i)
			{
				Byte* tempStore = &(buffer[i]);
				
				if (memcmp(tempStore, inputData, inputLength) == 0)
				{
					if (!localAddresses)
					{
						localAddresses = new SIZE_T[currentArrayLength];
					}
					
					if (arrayIndex >= currentArrayLength)
					{
						const unsigned int oldCurrentArrayLength = currentArrayLength;
						this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
						
						SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
						memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
						delete[] localAddresses;
						localAddresses = newAddressesArray;
					}
					
					localAddresses[arrayIndex++] = currentRegion.BaseAddress + i;
					++fileIndex;
				}
			}
		}
	
		if (arrayIndex > 0)
		{
			AtomicXAdd(this->mScanResultCount, arrayIndex);
			
			if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
			{
				AddResultsToCache(arrayIndex, localAddresses, NULL);
			}
			
			WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
			delete[] localAddresses;
		}
		else
		{
			if (localAddresses)
			{
				delete[] localAddresses;
			}
		}
		
		delete[] buffer;
		
		currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(regionData.AddressesFile);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData& regionData, const WString& value)
{
	const String addrFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	regionData.AddressesFile = CreateFile(addrFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	
	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;

	const wchar* const inputData = value.Begin();
	const int inputLengthInChars = value.GetLength();
	const int inputLength = value.GetLength() * sizeof(wchar);
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;

	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int arrayIndex = 0;
		unsigned int currentArrayLength = 256;
		SIZE_T* localAddresses = NULL;
		Vector<Byte> stringLengths;
		MemoryRegion& currentRegion = this->memRegions[i];
		
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{			
			for (SIZE_T i = 0; i < currentRegion.MemorySize; ++i)
			{
				const wchar* strPtr = (wchar*)&(buffer[i]);
				
				int outputLength = inputLengthInChars;
				if (localNullScan ? CompareStringNullCharW(strPtr, inputLength, inputData, &outputLength) : (memcmp(strPtr, inputData, inputLength) == 0))
				{
					if (!localAddresses)
					{
						localAddresses = new SIZE_T[currentArrayLength];

						stringLengths.SetCount(currentArrayLength);
					}
					
					if (arrayIndex >= currentArrayLength)
					{
						const unsigned int oldCurrentArrayLength = currentArrayLength;
						this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
						
						SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
						memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
						delete[] localAddresses;
						localAddresses = newAddressesArray;
						stringLengths.SetCount(currentArrayLength);
					}
					
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					stringLengths[arrayIndex++] = outputLength;
					
					++fileIndex;
				}
			}
		}
		
		delete[] buffer;
		
		if (arrayIndex > 0)
		{
			AtomicXAdd(this->mScanResultCount, arrayIndex);
			
			if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
			{
				AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
			}
				
			WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
			delete[] localAddresses;
		}
		else
		{
			if (localAddresses)
			{
				delete[] localAddresses;
			}
		}
		
		currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(regionData.AddressesFile);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

template <>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData& regionData, const String& value)
{
	const String addrFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	regionData.AddressesFile = CreateFile(addrFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	
	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;

	const char* const inputData = value.Begin();
	const int inputLength = value.GetLength();
	const bool localNullScan = GlobalScanParameter->ScanUntilNullChar;
	
	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int arrayIndex = 0;
		unsigned int currentArrayLength = 256;
		SIZE_T* localAddresses = NULL;
		Vector<Byte> stringLengths;
		MemoryRegion& currentRegion = this->memRegions[i];
		
		currentRegion.FileDataIndexes.StartIndex = fileIndex;

		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < currentRegion.MemorySize; i++)
			{
				const char* strPtr = (char*)&(buffer[i]);
				
				int outputLength = inputLength;
				if (localNullScan ? CompareStringNullCharA(strPtr, inputLength, inputData, &outputLength) : (memcmp(strPtr, inputData, inputLength) == 0))
				{
					if (!localAddresses)
					{
						localAddresses = new SIZE_T[currentArrayLength];
						stringLengths.SetCount(currentArrayLength);
					}
					if (arrayIndex >= currentArrayLength)
					{
						const unsigned int oldCurrentArrayLength = currentArrayLength;
						this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
						
						SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
						memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
						delete[] localAddresses;
						localAddresses = newAddressesArray;
						
						stringLengths.SetCount(currentArrayLength);
					}
					
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					stringLengths[arrayIndex++] = outputLength;
					
					++fileIndex;
				}
			}
		}
		
		delete[] buffer;
		
		if (arrayIndex > 0)
		{
			AtomicXAdd(this->mScanResultCount, arrayIndex);
			
			if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
			{
				AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
			}
				
			WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
			delete[] localAddresses;
		}
		else
		{
			if (localAddresses)
			{
				delete[] localAddresses;
			}
		}
		
		currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(regionData.AddressesFile);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

// Represents the default template worker function for the set of workers including specialized ones.
// This set of workers run the first scan sequence.
template <class T>
void MemoryScanner::FirstScanWorker(WorkerRegionParameterData& regionData, const T& value)
{
	const String addrFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	const String valuesFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData.WorkerIdentifier));
	regionData.AddressesFile = CreateFile(addrFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	regionData.ValuesFile = CreateFile(valuesFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	
	int fastScanAlignSize = GlobalScanParameter->CurrentScanFastScan ? sizeof(T) : 1;
	if (fastScanAlignSize == sizeof(__int64))
	{
		fastScanAlignSize = sizeof(int);
	}
	
	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;
	
	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		unsigned int arrayIndex = 0;
		unsigned int currentArrayLength = 256;
		
		MemoryRegion& currentRegion = this->memRegions[i];
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		SIZE_T* localAddresses = NULL;
		T* localValues = NULL;
		
		Byte* buffer = new Byte[currentRegion.MemorySize];
		if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
		{
			for (SIZE_T i = 0; i < currentRegion.MemorySize; i += fastScanAlignSize)
			{
				const T* tempStore = (T*)&(buffer[i]);

				if ((*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*tempStore, value))
				{
					if (!localAddresses || !localValues)
					{
						localAddresses = new SIZE_T[currentArrayLength];
						localValues = new T[currentArrayLength];
					}
					
					if (arrayIndex >= currentArrayLength)
					{
						const unsigned int oldCurrentArrayLength = currentArrayLength;
						this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
						
						SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
						memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
						delete[] localAddresses;
						localAddresses = newAddressesArray;
						
						T* newValuesArray = new T[currentArrayLength];
						memcpy(newValuesArray, localValues, oldCurrentArrayLength * sizeof(T));
						delete[] localValues;
						localValues = newValuesArray;
					}
					
					localAddresses[arrayIndex] = currentRegion.BaseAddress + i;
					localValues[arrayIndex++] = *tempStore;

					++fileIndex;
				}
			}
		}
		
		delete[] buffer;
		
		if (arrayIndex > 0)
		{
			AtomicXAdd(this->mScanResultCount, arrayIndex);
			
			if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
			{
				AddResultsToCache(arrayIndex, localAddresses, NULL);
			}

			WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
			delete[] localAddresses;
			
			WriteFile(regionData.ValuesFile, localValues, arrayIndex * sizeof(T), &numberOfBytesWritten, NULL);
			delete[] localValues;
		}
		else
		{
			if (localAddresses)
			{
				delete[] localAddresses;
				delete[] localValues;
			}
		}
		
		currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}

	CloseHandle(regionData.AddressesFile);
	CloseHandle(regionData.ValuesFile);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;

		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

// Initializes the first scan sequence. Call this function from the user interface.
template <class T>
void MemoryScanner::FirstScan()
{
	// Clear last scan's results.
	this->ClearSearchResults();

	SIZE_T incAddress = 0;
	MEMORY_BASIC_INFORMATION block;
	
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
		this->ScanCompleted();

		return;
	}
	
	// Set thread finish count to 0. This is needed to restart progress indication.
	RegionFinishCount = 0;
	threadIncrement = 0;
	
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
		this->ScanCompleted();
		
		return;
	}
	
	// Start worker threads using the regions that are found and readable.
#ifdef _MULTITHREADED
	threadPool.SetThreadPriority(this->mSettingsInstance->GetScanThreadPriority());	
#endif

	// Signal user interface with a count to set progress indicator to ready state.
	const int regionCount = this->memRegions.GetCount();
	this->ScanStarted(regionCount);
	
	// Assign compare function accordingly
	this->mCompareValues = new ValueComparator<T>(GlobalScanParameter->GlobalScanType);

	// Set up constant values for calculating the sublists.
	const int remainder = regionCount % threadCount;
	int workerListLength = regionCount / threadCount;

	for (int i = 0; i < threadCount;)
	{
		// Append default calculated count of regions to the current worker vector.
		const int currentLength = (i * workerListLength);

		// Calculate whether the calculated division remainder is equal to the current leftovers,
		// meaning that this is the last thread and the remainder should be appended.
		if (((currentLength + workerListLength) + remainder) == regionCount)
		{
			workerListLength += remainder;
		}

		WorkerRegionParameterData regionData;
		regionData.OriginalStartIndex = currentLength;
		regionData.Length = workerListLength;
		regionData.WorkerIdentifier = ++i;

		threadPool & THISBACK2(FirstScanWorker<T>, this->mWorkerFileOrder.Add(regionData), ((T)(reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->ScanValue));
	}
}

template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData& regionData, const ArrayOfBytes& value)
{
	const String addrOutFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData.WorkerIdentifier));

	regionData.AddressesFile = CreateFile(addrOutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile = CreateFile(addrFileOld, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;
	
	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			unsigned int arrayIndex = 0;
			unsigned int currentArrayLength = 256;
			SIZE_T* localAddresses = NULL;
			
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SetFilePointer(hFile, oldFileIndex * sizeof(SIZE_T), NULL, FILE_BEGIN);
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				ReadFile(hFile, addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; ++resultIndex)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					Byte* currentDataPtr = buffer + (currentResultPtr - currentRegion.BaseAddress);
					
					if (memcmp(currentDataPtr, value.Data, value.Size) == 0)
					{
						if (!localAddresses)
						{
							localAddresses = new SIZE_T[currentArrayLength];					
						}
						
						if (arrayIndex >= currentArrayLength)
						{
							const unsigned int oldCurrentArrayLength = currentArrayLength;
							this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
							
							SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
							memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
							delete[] localAddresses;
							localAddresses = newAddressesArray;
						}
						
						localAddresses[arrayIndex++] = currentResultPtr;
						++fileIndex;
					}
				}
				
				delete[] addressesFileBuffer;
			}

			if (arrayIndex > 0)
			{
				AtomicXAdd(this->mScanResultCount, arrayIndex);
				
				if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
				{
					AddResultsToCache(arrayIndex, localAddresses, NULL);
				}
				
				WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				delete[] localAddresses;
			}
			else
			{
				if (localAddresses)
				{
					delete[] localAddresses;
				}
			}
			
			delete[] buffer;
			
			currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		}

		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(hFile);
	CloseHandle(regionData.AddressesFile);
	
	FileDelete(addrFileOld);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData& regionData, const WString& value)
{
	const String addrOutFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData.WorkerIdentifier));

	regionData.AddressesFile = CreateFile(addrOutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile = CreateFile(addrFileOld, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;

	const int inputLengthInChars = value.GetLength();
	const int inputLength = value.GetLength() * sizeof(wchar);
	const wchar* const inputData = value.Begin();
	
	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			unsigned int arrayIndex = 0;
			unsigned int currentArrayLength = 256;
			SIZE_T* localAddresses = NULL;
			Vector<Byte> stringLengths;
			
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SetFilePointer(hFile, oldFileIndex * sizeof(SIZE_T), NULL, FILE_BEGIN);
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				ReadFile(hFile, addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; ++resultIndex)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					const wchar* currentDataPtr = (wchar*)(buffer + (currentResultPtr - currentRegion.BaseAddress));
					
					if (memcmp(currentDataPtr, inputData, inputLength) == 0)
					{
						if (!localAddresses)
						{
							localAddresses = new SIZE_T[currentArrayLength];
							stringLengths.SetCount(currentArrayLength);	
						}
						
						if (arrayIndex >= currentArrayLength)
						{
							const unsigned int oldCurrentArrayLength = currentArrayLength;
							this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
							
							SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
							memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
							delete[] localAddresses;
							localAddresses = newAddressesArray;
							stringLengths.SetCount(currentArrayLength);	
						}
						
						localAddresses[arrayIndex] = currentResultPtr;
						stringLengths[arrayIndex++] = inputLengthInChars;
						
						++fileIndex;
					}
				}
				
				delete[] addressesFileBuffer;
			}
			
			delete[] buffer;

			if (arrayIndex > 0)
			{
				AtomicXAdd(this->mScanResultCount, arrayIndex);
				
				if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
				{
					AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
				}
				
				WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				delete[] localAddresses;
			}
			else
			{
				if (localAddresses)
				{
					delete[] localAddresses;
				}
			}
			
			currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		}

		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(hFile);
	CloseHandle(regionData.AddressesFile);
	
	FileDelete(addrFileOld);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

template <>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData& regionData, const String& value)
{
	const String addrOutFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData.WorkerIdentifier));

	regionData.AddressesFile = CreateFile(addrOutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile = CreateFile(addrFileOld, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;

	const int inputLength = value.GetLength();

	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			unsigned int arrayIndex = 0;
			unsigned int currentArrayLength = 256;
			SIZE_T* localAddresses = NULL;
			Vector<Byte> stringLengths;
			
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SetFilePointer(hFile, oldFileIndex * sizeof(SIZE_T), NULL, FILE_BEGIN);
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				ReadFile(hFile, addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; ++resultIndex)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					const char* currentDataPtr = (char*)(buffer + (currentResultPtr - currentRegion.BaseAddress));
					
					if (memcmp(currentDataPtr, value, inputLength) == 0)
					{
						if (!localAddresses)
						{
							localAddresses = new SIZE_T[currentArrayLength];
							stringLengths.SetCount(currentArrayLength);					
						}
						
						if (arrayIndex >= currentArrayLength)
						{
							const unsigned int oldCurrentArrayLength = currentArrayLength;
							this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
							
							SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
							memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
							delete[] localAddresses;
							localAddresses = newAddressesArray;
							stringLengths.SetCount(currentArrayLength);
						}
						
						localAddresses[arrayIndex] = currentResultPtr;
						stringLengths[arrayIndex++] = inputLength;
						
						++fileIndex;
					}
				}
				
				delete[] addressesFileBuffer;
			}
			
			delete[] buffer;

			if (arrayIndex > 0)
			{
				AtomicXAdd(this->mScanResultCount, arrayIndex);
				
				if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
				{
					AddResultsToCache(arrayIndex, localAddresses, stringLengths.Begin());
				}
				
				WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				delete[] localAddresses;
			}
			else
			{
				if (localAddresses)
				{
					delete[] localAddresses;
				}
			}
			
			currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		}

		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	CloseHandle(hFile);
	CloseHandle(regionData.AddressesFile);
	
	FileDelete(addrFileOld);
	
	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

// This function is the default template for the set of specialized workers for the next scan.
template <class T>
void MemoryScanner::NextScanWorker(WorkerRegionParameterData& regionData, const T& value)
{
	const String addrOutFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.temp", regionData.WorkerIdentifier));
	const String valuesOutFile = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.temp", regionData.WorkerIdentifier));
	const String addrFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", regionData.WorkerIdentifier));
	const String valuesFileOld = AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.tempSCANNING", regionData.WorkerIdentifier));
	
	regionData.AddressesFile = CreateFile(addrOutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	regionData.ValuesFile = CreateFile(valuesOutFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	HANDLE hFile = CreateFile(addrFileOld, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	HANDLE hOldValues = NULL;

	if (GlobalScanParameter->GlobalScanType == SCANTYPE_CHANGED || GlobalScanParameter->GlobalScanType == SCANTYPE_UNCHANGED)
	{
		hOldValues = CreateFile(valuesFileOld, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	}

	unsigned int fileIndex = 0;
	DWORD numberOfBytesWritten;
	
	const unsigned int forLoopLength = regionData.OriginalStartIndex + regionData.Length;
	for (unsigned int i = regionData.OriginalStartIndex; i < forLoopLength; ++i)
	{
		MemoryRegion& currentRegion = this->memRegions[i];
		const unsigned int oldFileIndex = currentRegion.FileDataIndexes.StartIndex;
		currentRegion.FileDataIndexes.StartIndex = fileIndex;
		
		if (currentRegion.FileDataIndexes.ResultCount > 0)
		{
			unsigned int arrayIndex = 0;
			unsigned int currentArrayLength = 256;
			SIZE_T* localAddresses = NULL;
			T* localValues = NULL;
			
			Byte* buffer = new Byte[currentRegion.MemorySize];
			if (CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)currentRegion.BaseAddress, buffer, currentRegion.MemorySize, NULL))
			{
				SetFilePointer(hFile, oldFileIndex * sizeof(SIZE_T), NULL, FILE_BEGIN);
				SIZE_T* addressesFileBuffer = new SIZE_T[currentRegion.FileDataIndexes.ResultCount];
				ReadFile(hFile, addressesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(SIZE_T), &numberOfBytesWritten, NULL);

				T* valuesFileBuffer = NULL;
	
				if ((int)GlobalScanParameter->GlobalScanType >= (int)SCANTYPE_CHANGED)
				{
					SetFilePointer(hOldValues, oldFileIndex * sizeof(T), NULL, FILE_BEGIN);
					valuesFileBuffer = new T[currentRegion.FileDataIndexes.ResultCount];
					ReadFile(hOldValues, valuesFileBuffer, currentRegion.FileDataIndexes.ResultCount * sizeof(T), &numberOfBytesWritten, NULL);
				}
				
				for (unsigned int resultIndex = 0; resultIndex < currentRegion.FileDataIndexes.ResultCount; resultIndex++)
				{
					const SIZE_T currentResultPtr = addressesFileBuffer[resultIndex];
					const T* currentDataPtr = (T*)(buffer + (currentResultPtr - currentRegion.BaseAddress));
					
					bool compareSucceeded = false;
					if (GlobalScanParameter->GlobalScanType == SCANTYPE_CHANGED)
					{
						compareSucceeded = !(*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*currentDataPtr, valuesFileBuffer[arrayIndex]);
					}
					else if (GlobalScanParameter->GlobalScanType >= (int)SCANTYPE_UNCHANGED)
					{
						compareSucceeded = (*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*currentDataPtr, valuesFileBuffer[arrayIndex]);
					}
					else
					{
						compareSucceeded = (*reinterpret_cast<ValueComparator<T>*>(this->mCompareValues))(*currentDataPtr, value);
					}

					if (compareSucceeded)
					{
						if (!localAddresses || !localValues)
						{
							localAddresses = new SIZE_T[currentArrayLength];
							localValues = new T[currentArrayLength];			
						}
						
						if (arrayIndex >= currentArrayLength)
						{
							const unsigned int oldCurrentArrayLength = currentArrayLength;
							this->ReallocateMemoryScannerBufferCounter(&currentArrayLength);
							
							SIZE_T* newAddressesArray = new SIZE_T[currentArrayLength];
							memcpy(newAddressesArray, localAddresses, oldCurrentArrayLength * sizeof(SIZE_T));
							delete[] localAddresses;
							localAddresses = newAddressesArray;
							
							T* newValuesArray = new T[currentArrayLength];
							memcpy(newValuesArray, localValues, oldCurrentArrayLength * sizeof(T));
							delete[] localValues;
							localValues = newValuesArray;
						}
						
						localAddresses[arrayIndex] = currentResultPtr;
						localValues[arrayIndex++] = *currentDataPtr;
						
						++fileIndex;
					}
				}
				
				delete[] addressesFileBuffer;
				
				if (valuesFileBuffer)
				{
					delete[] valuesFileBuffer;
				}
			}
			
			delete[] buffer;

			if (arrayIndex > 0)
			{
				AtomicXAdd(this->mScanResultCount, arrayIndex);
				
				if (CachedAddresses.GetCount() < MEMORYSCANNER_CACHE_LIMIT)
				{
					AddResultsToCache(arrayIndex, localAddresses, NULL);
				}
				
				WriteFile(regionData.AddressesFile, localAddresses, arrayIndex * sizeof(SIZE_T), &numberOfBytesWritten, NULL);
				delete[] localAddresses;
				
				WriteFile(regionData.ValuesFile, localValues, arrayIndex * sizeof(T), &numberOfBytesWritten, NULL);
				delete[] localValues;
			}
			else
			{
				if (localAddresses && localValues)
				{
					delete[] localAddresses;
					delete[] localValues;
				}
			}
			
			currentRegion.FileDataIndexes.ResultCount = arrayIndex;
		}

		this->UpdateScanningProgress(AtomicInc(RegionFinishCount));
	}
	
	if (hOldValues)
	{
		CloseHandle(hOldValues);
	}
	
	CloseHandle(hFile);
	CloseHandle(regionData.AddressesFile);
	CloseHandle(regionData.ValuesFile);
	
	FileDelete(addrFileOld);
	FileDelete(valuesFileOld);

	if (AtomicInc(threadIncrement) >= threadCount)
	{
		delete this->mCompareValues;
		this->mCompareValues = NULL;
		
		this->ScanRunning = false;
		this->ScanCompleted();
	}
}

// Initializes the next scan sequence. Call this function from the user interface.
template <class T>
void MemoryScanner::NextScan()
{
	// Clear partial search results for next scanning.
	this->mScanResultCount = 0;
	CachedAddresses.Clear();
	
	this->ScanRunning = true;

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
				this->ScanCompleted();
			
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
				this->ScanCompleted();
			
				return;
			}
			
			FileMove(addrFn, AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Addresses%i.tempSCANNING", i)));
			FileMove(valFn, AppendFileName(mMemoryScanner->GetTempFolderPath(), Format("Values%i.tempSCANNING", i)));
		}
	}
	
	// Reset progress indication bar in the GUI.
	RegionFinishCount = 0;
	threadIncrement = 0;
	this->ScanStarted(this->memRegions.GetCount());
	
	// Assign compare function accordingly
	this->mCompareValues = new ValueComparator<T>(GlobalScanParameter->GlobalScanType);
	
	// Set thread priority for the workers ran by this scan session.
#ifdef _MULTITHREADED
	threadPool.SetThreadPriority(this->mSettingsInstance->GetScanThreadPriority());
#endif

	// Start worker threads accordingly to previous scan.
	for (int i = 0; i < this->mWorkerFileOrder.GetCount(); i++)
	{
		threadPool & THISBACK2(NextScanWorker<T>, this->mWorkerFileOrder[i], ((T)(reinterpret_cast<ScanParameters<T>*>(GlobalScanParameter))->ScanValue));
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
template <class T>
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
template <class T>
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