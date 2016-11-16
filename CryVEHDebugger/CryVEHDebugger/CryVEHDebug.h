#pragma once

#include <Windows.h>
#include <vector>

// ----------------------------------------------------------------------------------------------------------

// Indicates the type of breakpoint.
enum CryBpType
{
	SoftwareBreakpoint,
	HardwareBreakpoint
};

// Represents the size of a hardware breakpoint. The sizes as integer value are different from the actual 
// enum definition because the flags need to be set accordingly.
enum CryHwbpSize
{
	HWBP_SIZE_1 = 0,
	HWBP_SIZE_2 = 1,
	HWBP_SIZE_4 = 3,
	HWBP_SIZE_8 = 2
};

// Represents the type of hardware breakpoint.
enum CryHwbpType
{
	HWBP_TYPE_EXECUTE = 0,
	HWBP_TYPE_READWRITE = 3,
	HWBP_TYPE_WRITE = 1
};

// Represents a breakpoint that the VEH debugger can set.
struct CryBreakpoint
{
	SIZE_T Address;
	CryBpType BreakpointType;
	int HitCount;

	union
	{
		BYTE OldInstruction;
		BYTE ProcessorTrapFlag;
	};
	
	bool Disabled;
	std::vector<DWORD> AffectedThreads;
	DWORD DebugRegister;
	CryHwbpSize HardwareSize;
	CryHwbpType HardwareType;
	bool MustSetHardware;

	CryBreakpoint()
	{
		this->Address = 0;
		this->BreakpointType = SoftwareBreakpoint;
		this->HitCount = 0;
		this->OldInstruction = 0;
		this->Disabled = false;
		this->DebugRegister = 0;
		this->HardwareSize = HWBP_SIZE_1;
		this->HardwareType = HWBP_TYPE_EXECUTE;
		this->MustSetHardware = false;
	}
};

// Forward definition of the function, it is declared somewhere else.
DWORD __stdcall DebuggerLoop(LPVOID lpParam);

// Represents the debugger itself.
class CryVEHDebugger
{
private:
	bool mIsRunning;
	std::vector<CryBreakpoint> breakpointList;
	
	// Singleton code: private constructor, destructor and copy constructors.
	CryVEHDebugger();
	~CryVEHDebugger();

	CryVEHDebugger(CryVEHDebugger const&);
	void operator=(CryVEHDebugger const&);
public:
	static CryVEHDebugger* GetInstance()
	{
		static CryVEHDebugger instance;
		return &instance;
	}

	void Start();
	void Stop();

	const bool AddSoftwareBreakpoint(const SIZE_T address);
	const bool AddHardwareBreakpoint(const SIZE_T address, CryHwbpSize size, CryHwbpType type);

	const bool DisableBreakpoint(const SIZE_T address);
	const bool RemoveBreakpoint(const SIZE_T address);

	const bool IsRunning() const;
	const int GetBreakpointCount() const;
	const int FindBreakpoint(const SIZE_T address) const;
};

// ----------------------------------------------------------------------------------------------------------

#define COMM_MAPPING_SIZE					65536 // 64 kb size of the communications shared memory.
#define MAX_ACTION_COUNT					8

// The following are action code definitions.
#define ACTION_SET_HARDWARE_BREAKPOINT		0x1
#define ACTION_SET_BREAKPOINT				0x2
#define ACTION_DISABLE_BREAKPOINT			0x3
#define ACTION_REMOVE_BREAKPOINT			0x4

// Represents an action in the queue of the debugger.
typedef struct _CRY_ACTION_QUEUE_ITEM
{
	DWORD ActionCode;
	void* ParameterData;
} CRY_ACTION_QUEUE_ITEM;

// Represents the header for the VEH debugger communications channel.
// It should be mapped at the base address of the memory mapped file and used to navigate further into the data.
typedef struct _CRY_VEH_COMMUNICATION_HEADER
{
	// The size of the entire communication structure, in bytes.
	DWORD SizeInBytes;

	// Structure that tracks actions.
	struct
	{
		// The maximum amount of allocated queue items is 8!
		DWORD ActionCount;
		CRY_ACTION_QUEUE_ITEM ActionData[MAX_ACTION_COUNT];
	} ActionQueue;

	// Communication synchronization variable. Who is currently accessing the structure?
	BOOL CurrentlyBeingAccessed;

} CRY_VEH_COMMUNICATION_HEADER;

// ----------------------------------------------------------------------------------------------------------

// Utility functions for the VEH debugger.

void EnumerateThreads(std::vector<DWORD>& threads);
void BreakpointRoutine(CryBreakpoint* pHwbp, const DWORD threadId);