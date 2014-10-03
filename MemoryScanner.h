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
	
	// This parameter contains the size of an array of bytes or the length of a string in case of such a scan.
	// If the scan value type is not one of these, this parameter is ignored.
	unsigned int ValueSize;
};

// Scan parameters given to a new scan.
template <class T>
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
	
	// We should at least manually set the second field in order to prevent mahem in the user interface.
	SearchResultCacheEntry()
	{
		this->Address = 0;
		this->StaticAddress = false; // Accidentally true could cause unexplainable user interface behavior.
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
	int WorkerIdentifier;
	unsigned int OriginalStartIndex;
	unsigned int Length;
	
	// File handles.
	HANDLE AddressesFile;
	HANDLE ValuesFile;
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

template <class T>
bool __fastcall CompareEqual(const T& input, const T& expected);

template <class T>
bool __fastcall CompareSmaller(const T& input, const T& expected);

template <class T>
bool __fastcall CompareGreater(const T& input, const T& expected);

template <class T>
bool __fastcall CompareUnknownInitialValue(const T& input, const T& expected);

// Defines the compare function functor, customizable with template type and parameters using the constructor.
struct CompareFunction { };

template <class T>
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
	HANDLE mOpenedProcessHandle;
	int mLoadedProcessId;
	String mProcessName;
	bool isX86Process;
	bool ScanRunning;
	SettingsFile* mSettingsInstance;
	CompareFunction* mCompareValues;
	int threadCount;
	
	// Vector that contains the order of worker completions. Needed to ensure next scan accuracy.
	Vector<WorkerRegionParameterData> mWorkerFileOrder;
	
	// Vector that contains the memory pages of the currently opened process. Beware that a First-Scan refreshes the pages entirely.
	Vector<MemoryRegion> memRegions;
	
	// Resultcount variable that contains the result count of the most recent memory scan.
	int mScanResultCount;
	
	typedef MemoryScanner CLASSNAME;

	template <class T>
	void FirstScanWorker(WorkerRegionParameterData& regionData, const T& value);
	
	template <class T>
	void NextScanWorker(WorkerRegionParameterData& regionData, const T& value);
	
	// Reallocation counter function as a workaround for the excessive buffer allocation problem on older systems.
	inline void ReallocateMemoryScannerBufferCounter(unsigned int* const length);
	
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

	bool InitializeExistingProcess(const int processId, const String& exeTitle);
	bool InitializeNewProcess(const char* exetitle, int* const pProcessId);
	
	void CloseProcess();
	void ClearSearchResults();
	
	template <class T>
	void FirstScan();
	
	template <class T>
	void NextScan();
	
	template <class T>
	void Poke(const SIZE_T address, const T& value);
	
	// Size parameter is optional. If AOB or String types are used, parameter is used, otherwise ignored.
	template <class T>
	bool Peek(const SIZE_T address, const unsigned int size, T* outBuffer) const;
	
	const String& GetProcessName() const;
	const bool IsX86Process() const;
	const int GetProcessId() const;
	HANDLE GetHandle() const;
	bool IsScanRunning() const;
	const Vector<WorkerRegionParameterData>& QueryWorkerData() const;
	const int GetScanResultCount() const;
	const char* GetTempFolderPath() const;
	const int GetSystemThreadCount() const;
	
	Callback1<int> ScanStarted;
	Callback ScanCompleted;
	Callback1<MemoryScannerError> ErrorOccured;
	Callback1<Atomic> UpdateScanningProgress;
};

// User interface would like access to the cache containers.
extern Vector<SearchResultCacheEntry> CachedAddresses;
extern Vector<Value> CachedValues;

template <class T>
void AddResultsToCache(const int Resultcount, const SIZE_T* AddressBuffer, const T* ValuesBuffer);

#endif