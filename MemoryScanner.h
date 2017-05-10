#ifndef _MemoryScanner_h_
#define _MemoryScanner_h_

#include <Core/Core.h>

using namespace Upp;

// Memory protection constant definitions. Configurable search by the settings GUI.
#define MEM_WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define MEM_EXECUTABLE (PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE)
#define MEM_COPYONWRITE (PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)

#include "MemoryScannerContext.h"
#include "CrySearchLibrary/SDK/CrySearch.h"

// Memory scanner comparison types.
enum MemoryScanType
{
	SCANTYPE_UNKNOWN_INITIAL_VALUE,
	SCANTYPE_EXACTVALUE,
	SCANTYPE_SMALLERTHAN,
	SCANTYPE_GREATERTHAN,
	SCANTYPE_VALUE_IN_BETWEEN,
	SCANTYPE_CHANGED,
	
	// The same comparetor function applies for the scan types below. Do not add a scan type that requires a different comparetor.
	SCANTYPE_UNCHANGED,
	SCANTYPE_INCREASED,
	SCANTYPE_DECREASED
};

// Generalisation struct that can be used to save class instances with template parameter lists.
struct ScanParameterBase
{
	// Indicates whether a fast (aligned) scan should be executed.
	bool CurrentScanFastScan;
	
	// The type of scan that should be executed.
	MemoryScanType GlobalScanType;
	
	// The value type (sizeof) of the value that should be scanned for.
	CCryDataType GlobalScanValueType;
	
	// Are we returning search results in hexadecimal?
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
		this->GlobalScanValueType = CRYDATATYPE_UNKNOWN;
		this->CurrentScanHexValues = false;
		this->ValueSize = 0;
		this->ScanUntilNullChar = false;
	};
};

// Scan parameters given to a new scan.
template <typename T>
struct ScanParameters : public ScanParameterBase
{
	// The value to scan a process' memory for. If the user wants to scan for a value that is
	// in between of two values, this variable is the first value of the two.
	T ScanValue;
	
	// If the user wants tot scan for a value that is in between of two values, this variable is
	// the second of the two. Otherwise, this variable is not used.
	T OuterScanValue;
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

// Represents an array of bytes to be searched for in memory.
struct ArrayOfBytes
{
	// The bytes buffer.
	Byte* Data;
	
	// The size of the buffer.
	int Size;
	
	// The ArrayOfBytes default constructor.
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
	
	// The ArrayOfBytes default destructor.
	~ArrayOfBytes()
	{
		if (this->Data)
		{
			delete[] this->Data;
		}
		
		this->Data = NULL;
		this->Size = 0;
	};
	
	// Allocates a buffer for this instance.
	void Allocate(int size)
	{
		this->Data = new Byte[size];
		this->Size = size;
	};
	
	// The ArrayOfBytes copy constructor.
	ArrayOfBytes(ArrayOfBytes const& next)
	{
		this->CopyConstructAob(next);
	};
	
	// The ArrayOfBytes assignment operator.
	ArrayOfBytes& operator=(ArrayOfBytes const& next)
	{
		this->CopyConstructAob(next);
		return *this;
	};

private:
	// Copy constructs this instance from another array of bytes.
	inline void CopyConstructAob(ArrayOfBytes const& next)
	{
		this->Allocate(next.Size);
		memcpy(this->Data, next.Data, next.Size);
	};
};

// Compare functions are listed below.

template <typename T>
const bool CompareEqual(const T& input, const T& expected);

template <typename T>
const bool CompareSmaller(const T& input, const T& expected);

template <typename T>
const bool CompareGreater(const T& input, const T& expected);

template <typename T>
const bool CompareInBetween(const T& input, const T& expected);

template <typename T>
const bool CompareUnknownInitialValue(const T& input, const T& expected);

#define STRING_MAX_UNTIL_NULL	0x100

const bool CompareStringNullCharA(const char* input, const int inputLength, const char* expected, int* const outputLength);
const bool CompareStringNullCharW(const wchar* input, const int inputLength, const wchar* expected, int* const outputLength);

// Compare function type definition.
template <typename T>
using CompareFunctionType = const bool (*)(const T& input, const T& expected);

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
	int threadCount;
	bool mReadOnly;
	
	// The memory scanner object has the longest lifetime. It should take ownership of the thread pool.
	CoWork mThreadPool;
	
	// Vector that contains the order of worker completions. Needed to ensure next scan accuracy.
	Vector<MemoryScannerWorkerContext> mWorkerFileOrder;
	
	// Vector that contains the memory pages of the currently opened process. Beware that a First-Scan refreshes the pages entirely.
	Vector<MemoryRegion> memRegions;
	
	// Resultcount variable that contains the result count of the most recent memory scan.
	volatile Atomic mScanResultCount;
	
	// Indicates how many regions have been processed.
	volatile Atomic mRegionFinishCount;
	
	typedef MemoryScanner CLASSNAME;
	
	// Handle memory scanner cache and file output.
	void HandleScanCacheFileOutput(MemoryScannerWorkerContext* const context, const Bits& AddressBuffer, const void* ValuesBuffer, const Byte* lengthBuffers
		, const unsigned int addrIndex, const unsigned int valueIndex, const unsigned int typeSize, const unsigned int alignSize);
	
	// Functions that assign the correct compare function using the user selected scan type, and fire of the workers accordingly.
	template <typename T>
	CompareFunctionType<T> GetCompareFunction();

	// Workers are now divided in phases such that the amount of templated code can be minimized.
	// The first phase of each worker is the prologue: Setting up the context.
	void FirstWorkerPrologue(MemoryScannerWorkerContext* const context);
	void NextWorkerPrologue(MemoryScannerWorkerContext* const context);
	
	// The last phase of the workers is the epilogue. In this phase, resources are released and the scan is finalized.
	void FirstWorkerEpilogue(MemoryScannerWorkerContext* const context);
	void NextWorkerEpilogue(MemoryScannerWorkerContext* const context);
	
	// Templated worker function for the first scans.
	template <typename T>
	void FirstScanWorker(MemoryScannerWorkerContext* const context, const T& value, CompareFunctionType<T> cmp);
	
	// Templated worker function for the refresh scans.
	template <typename T>
	void NextScanWorker(MemoryScannerWorkerContext* const context, const T& value, CompareFunctionType<T> cmp);
	
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
	
	void FirstScan();
	void NextScan();
	
	// Memory scanner poke functions (Writing to memory).
	void Poke(const SIZE_T address, const void* value, const unsigned int size) const;
	void PokeB(const SIZE_T address, const ArrayOfBytes& value) const;
	void PokeA(const SIZE_T address, const String& value) const;
	void PokeW(const SIZE_T address, const WString& value) const;
	
	// Memory scanner peek function (Reading from memory).
	const bool Peek(const SIZE_T address, const unsigned int size, void* const outBuffer) const;
	const bool PeekB(const SIZE_T address, const unsigned int size, ArrayOfBytes& outBuffer) const;
	const bool PeekW(const SIZE_T address, const unsigned int size, WString& outBuffer) const;
	const bool PeekA(const SIZE_T address, const unsigned int size, String& outBuffer) const;
	
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