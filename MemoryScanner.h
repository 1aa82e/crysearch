#ifndef _MemoryScanner_h_
#define _MemoryScanner_h_

#include <Core/Core.h>

using namespace Upp;

// Memory protection constant definitions. Configurable search by the settings GUI.
#define MEM_WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define MEM_EXECUTABLE (PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE)
#define MEM_COPYONWRITE (PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)

#include "SettingsFile.h"

// Defines the valuetypes that are scannable by the memory scanner.
enum MemoryScanValueType
{
	VALUETYPE_UNKNOWN,
	VALUETYPE_BYTE,
	VALUETYPE_2BYTE,
	VALUETYPE_4BYTE,
	VALUETYPE_8BYTE,
	VALUETYPE_FLOAT,
	VALUETYPE_DOUBLE,
	VALUETYPE_STRING,
	VALUETYPE_WSTRING,
	VALUETYPE_AOB
};

// Memory scanner comparison types.
enum MemoryScanType
{
	SCANTYPE_UNKNOWN_INITIAL_VALUE,
	SCANTYPE_EXACTVALUE,
	SCANTYPE_SMALLERTHAN,
	SCANTYPE_GREATERTHAN,
	SCANTYPE_CHANGED,
	
	// The same comparetor function applies for the scan types below. Do not add a scan type that requires a different comparetor.
	SCANTYPE_UNCHANGED,
	SCANTYPE_INCREASED,
	SCANTYPE_DECREASED
};

// Generalisation struct that can be used to save class instances with template parameter lists.
struct ScanParameterBase
{
	bool CurrentScanFastScan;
	MemoryScanType GlobalScanType;
	MemoryScanValueType GlobalScanValueType;
	bool CurrentScanHexValues;
	
	// This parameter contains the size of an array of bytes or the length of a string in case of such a scan.
	// If the scan value type is not one of these, this parameter is ignored.
	unsigned int ValueSize;
	
	// When searching for strings, it is possible to match strings until null chars are hit. The threshold to
	// avoid CrySearch from reading excessive amounts of memory into a string is 0x100.
	bool ScanUntilNullChar;
	
	// Default constructor should help preventing bogus values.
	ScanParameterBase()
	{
		this->CurrentScanFastScan = true;
		this->GlobalScanType = SCANTYPE_UNKNOWN_INITIAL_VALUE;
		this->GlobalScanValueType = VALUETYPE_UNKNOWN;
		this->CurrentScanHexValues = false;
		this->ValueSize = 0;
		this->ScanUntilNullChar = false;
	};
};

// Scan parameters given to a new scan.
template <typename T>
struct ScanParameters : public ScanParameterBase
{
	T ScanValue;
};

// Global variable to store scan parameters because of the performance issues a function parameter brings in.
extern ScanParameterBase* GlobalScanParameter;

// Function to delete temporary files used by the scanner.
__declspec(noinline) void DeleteTemporaryFiles();

// Memory scanner error definitions. Only for usage by the MemoryScanner class or one of it's child/friends.
enum MemoryScannerError
{
	OPENPROCESSFAILED,
	PROCESSWASTERMINATED,
	NOREADABLEMEMORYFOUND,
	NATIVEROUTINEGETPROCFAILED,
	DATAFILENOTFOUND
};

// Represents a search result cache entry.
struct SearchResultCacheEntry : Moveable<SearchResultCacheEntry>
{
#ifdef _WIN64
	__int64 Address;
#else
	int Address;
#endif

	// Indicates whether the address should be displayed as a static one in the user interface.
	bool StaticAddress;
	
	// Indicates the length of a string or wstring in the search results.
	Byte StringLength;
	
	// We should at least manually set the second field in order to prevent mahem in the user interface.
	SearchResultCacheEntry()
	{
		this->Address = 0;
		this->StaticAddress = false; // Accidentally true could cause unexplainable user interface behavior.
		this->StringLength = 0;
	};
	
	// Default constructor for adding cache entries.
#ifdef _WIN64
	SearchResultCacheEntry(const __int64 address, const bool staticAddr)
#else
	SearchResultCacheEntry(const int address, const bool staticAddr)
#endif
	{
		this->Address = address;
		this->StaticAddress = staticAddr;
	};
};

// Represents a memory region found by the memory scanner.
struct MemoryRegion : Moveable<MemoryRegion>
{
	SIZE_T BaseAddress;
	SIZE_T MemorySize;
	
	struct
	{
		unsigned int ResultCount;
		unsigned int StartIndex;
	}
	FileDataIndexes;
};

// Defines a set of parameters needed for a new scan.
struct WorkerRegionParameterData : Moveable<WorkerRegionParameterData>
{
	// Identifies the worker.
	int WorkerIdentifier;
	
	// Indicates where the worker input starts in the memory page vector.
	unsigned int OriginalStartIndex;
	
	// Indicates how long the input in the memory page vector is for this worker.
	unsigned int Length;
	
	// Worker-wide variable that indicates whether it has completed.
	bool FinishedWork;
	
	// Default constructor, initializing all variables to defaults.
	WorkerRegionParameterData()
	{
		this->WorkerIdentifier = 0;
		this->OriginalStartIndex = 0;
		this->Length = 0;
		this->FinishedWork = false;
	};
};

// Represents an array of bytes to be searched for in memory.
struct ArrayOfBytes
{
	Byte* Data;
	int Size;
	
	ArrayOfBytes()
	{
		this->Data = NULL;
		this->Size = 0;
	};

	// Assignment constructor, does not copy the data!
	ArrayOfBytes(Byte* const data, const int size)
	{
		this->Data = data;
		this->Size = size;
	};

	~ArrayOfBytes()
	{
		if (this->Data)
		{
			delete[] this->Data;
		}
		
		this->Data = NULL;
		this->Size = 0;
	};

	void Allocate(int size)
	{
		this->Data = new Byte[size];
		this->Size = size;
	};
	
	ArrayOfBytes(ArrayOfBytes const& next)
	{
		this->CopyConstructAob(next);
	};

	ArrayOfBytes& operator=(ArrayOfBytes const& next)
	{
		this->CopyConstructAob(next);
		return *this;
	};

private:
	inline void CopyConstructAob(ArrayOfBytes const& next)
	{
		this->Allocate(next.Size);
		memcpy(this->Data, next.Data, next.Size);
	};
};

template <typename T>
bool __fastcall CompareEqual(const T& input, const T& expected);

template <typename T>
bool __fastcall CompareSmaller(const T& input, const T& expected);

template <typename T>
bool __fastcall CompareGreater(const T& input, const T& expected);

template <typename T>
bool __fastcall CompareUnknownInitialValue(const T& input, const T& expected);

#define STRING_MAX_UNTIL_NULL	0x100

bool __fastcall CompareStringNullCharA(const char* input, const int inputLength, const char* expected, int* const outputLength);
bool __fastcall CompareStringNullCharW(const wchar* input, const int inputLength, const wchar* expected, int* const outputLength);

// Defines the compare function functor, customizable with template type and parameters using the constructor.
struct CompareFunction { };

template <typename T>
struct ValueComparator : public CompareFunction
{
	bool (__fastcall* function)(const T&, const T&);
	
	ValueComparator(MemoryScanType type)
	{
		switch (type)
		{
			case SCANTYPE_UNKNOWN_INITIAL_VALUE:
				this->function = CompareUnknownInitialValue;
				break;
			case SCANTYPE_EXACTVALUE:
				this->function = CompareEqual;
				break;
			case SCANTYPE_SMALLERTHAN:
				this->function = CompareSmaller;
				break;
			case SCANTYPE_GREATERTHAN:
				this->function = CompareGreater;
				break;
			case SCANTYPE_CHANGED:
				this->function = CompareEqual;
				break;
			case SCANTYPE_UNCHANGED:
				this->function = CompareEqual;
				break;
			case SCANTYPE_INCREASED:
				this->function = CompareGreater;
				break;
			case SCANTYPE_DECREASED:
				this->function = CompareSmaller;
				break;
			default:
				this->function = NULL;
				break;
		}
	};
	
	bool operator ()(const T& input, const T& expected)
	{
		return this->function(input, expected);
	};
};

// The memory scanning class. Used for main memory scanning and reading.
class MemoryScanner
{
private:
	// Information about the opened process.
	HANDLE mOpenedProcessHandle;
	int mLoadedProcessId;
	String mProcessName;
	bool isX86Process;
	bool mProcessSuspended;
	
	// Memory scanner control variables.
	bool ScanRunning;
	SettingsFile* mSettingsInstance;
	CompareFunction* mCompareValues;
	int threadCount;
	bool mReadOnly;
	
	// The memory scanner object has the longest lifetime. It should take ownership of the thread pool.
	CoWork mThreadPool;
	
	// Vector that contains the order of worker completions. Needed to ensure next scan accuracy.
	Vector<WorkerRegionParameterData> mWorkerFileOrder;
	
	// Vector that contains the memory pages of the currently opened process. Beware that a First-Scan refreshes the pages entirely.
	Vector<MemoryRegion> memRegions;
	
	// Resultcount variable that contains the result count of the most recent memory scan.
	volatile Atomic mScanResultCount;
	
	// Indicates how many regions have been processed.
	volatile Atomic mRegionFinishCount;
	
	typedef MemoryScanner CLASSNAME;

	template <typename T>
	void FirstScanWorker(WorkerRegionParameterData* const regionData, const T& value);
	
	template <typename T>
	void NextScanWorker(WorkerRegionParameterData* const regionData, const T& value);
	
	// Singleton code: private constructor, destructor and copy constructors.
	MemoryScanner();
	~MemoryScanner();
	
	MemoryScanner(MemoryScanner const&);
	void operator=(MemoryScanner const&);
public:
	static MemoryScanner* GetInstance()
	{
		static MemoryScanner instance;
		return &instance;
	}

	bool InitializeExistingProcess(const int processId, const char* exeTitle, const bool readOnly);
	bool InitializeNewProcess(const char* exetitle, const DWORD flags, const char* args, int* const pProcessId);
	
	void CloseProcess();
	void ClearSearchResults();
	
	template <typename T>
	void FirstScan();
	
	template <typename T>
	void NextScan();
	
	template <typename T>
	void Poke(const SIZE_T address, const T& value);
	
	// Size parameter is optional. If AOB or String types are used, parameter is used, otherwise ignored.
	template <typename T>
	bool Peek(const SIZE_T address, const unsigned int size, T* outBuffer) const;
	
	const bool IsProcessSuspended() const;
	void ResetSuspendedState();
	
	const String& GetProcessName() const;
	const bool IsX86Process() const;
	const int GetProcessId() const;
	HANDLE GetHandle() const;
	bool IsScanRunning() const;
	const int GetScanResultCount() const;
	const char* GetTempFolderPath() const;
	const int GetSystemThreadCount() const;
	const bool IsReadOnlyOperationMode() const;
	const int GetRegionFinishedCount() const;
	
	// Workflow control functions for memory scanner synchronization.
	const bool GetIsWorkCompleted() const;
	void SetWorkCompleted();
	
	Callback1<int> ScanStarted;
	Callback1<MemoryScannerError> ErrorOccured;
	Callback1<int> UpdateScanningProgress;
};

// User interface would like access to the cache containers.
extern Vector<SearchResultCacheEntry> CachedAddresses;

#endif