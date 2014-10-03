#ifndef _CrySearch_CryDebugger_h_
#define _CrySearch_CryDebugger_h_

#include <Core/Core.h>

using namespace Upp;

// RTTI didn't quite work out so I switched to an extra variable.
#define BPTYPE_SOFTWARE 1
#define BPTYPE_HARDWARE 2

#include "AsyncDisassembler.h"

// Represents a part of dissected stack around ESP when a breakpoint was hit.
struct StackViewData : Moveable<StackViewData>
{
	SIZE_T StackAddress;
	SIZE_T StackValue;
};

// Field count definitions
#define REGISTERCOUNT_86	9
#define REGISTERCOUNT_64	15

// Generalizes a templated thread context that differs between x86 and x64.
struct CryThreadContextBase
{

};

// A thread context type can be stored in this structure.
template <class T>
struct CryThreadContext : public CryThreadContextBase
{
	T ThreadContext;
};

// Represents a breakpoint, optionally a hardware breakpoint.
struct DbgBreakpoint : Moveable<DbgBreakpoint>
{
	// Indicates the type of breakpoint. The type can be either BPTYPE_SOFTWARE or BPTYPE_HARDWARE.
	BOOLEAN BpType;
	
	// The address and hit count of the breakpoint.
	SIZE_T Address;
	int HitCount;
	
	// Indicates whether a breakpoint is in disabled state.
	BOOLEAN Disabled;
	
	// Contains the old instruction byte that is replaced with INT3 when a software breakpoint is placed.
	// In case of a hardware breakpoint, this field is used to indicate a trap flag.
	union
	{
		BYTE OldInstruction;
		BYTE ProcessorTrapFlag;
	};
	
	// Represents snapshot data that is captured when a breakpoint is hit.
	struct
	{
		// Indicates the amount of fields the thread context contains. Since this can differ between architectures it should be saved.
		int RegisterFieldCount;
		
		// Contains the line of disassembly that triggered the breakpoint.
		DisasmLine DisassemblyAccessLine;

		// Contains the snapshot of the processor registers.
		CryThreadContextBase* ThreadContextContainer;
		
		// Contains the stack view dissection at the moment of breakpoint hit.
		Vector<StackViewData> StackView;
		
		// Contains the call stack at the moment of breakpoint hit.
		Vector<Win32StackTraceEntry> CallStackView;
		
		// Releases memory used by the thread context.
		inline void Release()
		{
			if (this->ThreadContextContainer)
			{
				this->RegisterFieldCount = 0;
				delete this->ThreadContextContainer;
				this->ThreadContextContainer = NULL;
			}
		};
		
	} BreakpointSnapshot;
	
	// The thread context pointer must be set to NULL.
	DbgBreakpoint()
	{
		this->BreakpointSnapshot.RegisterFieldCount = 0;
		this->BreakpointSnapshot.ThreadContextContainer = NULL;
	};
};

// Represents the size of a hardware breakpoint. The sizes as integer value are different from the actual enum declaration
// because the flags need to be set accordingly.
typedef enum _HWBP_SIZE
{
	HWBP_SIZE_1 = 0,
	HWBP_SIZE_2 = 1,
	HWBP_SIZE_4 = 3,
	HWBP_SIZE_8 = 2
} HWBP_SIZE;

// Represents the type of hardware breakpoint.
typedef enum _HWBP_TYPE
{
	HWBP_TYPE_EXECUTE = 0,
	HWBP_TYPE_READWRITE = 3,
	HWBP_TYPE_WRITE = 1
} HWBP_TYPE;

// Represents a hardware breakpoint, which is an extension to the base breakpoint.
struct HardwareBreakpoint : public DbgBreakpoint
{
	Vector<DWORD> ThreadId;
	HWBP_TYPE Type;
	HWBP_SIZE Size;
	DWORD DebugRegister;
	bool MustSet;
	SIZE_T PreviousInstructionAddress;
	
	// Finds out whether a hardware breakpoint was already set at a specific thread.
	const bool IsSet(const DWORD threadId) const
	{
		for (int i = 0; i < this->ThreadId.GetCount(); i++)
		{
			if (this->ThreadId[i] == threadId)
			{
				return true;
			}
		}
		
		return false;
	}
};

// Data container passed to the debugger event to indicate an unhandled exception.
struct UnhandledExceptionData
{
	SIZE_T ExceptionAddress;
	LONG ExceptionCode;
	int UserResponse;
};

// Represents the type of debugger event that occured.
enum DebugEvent
{
	// Error enums
	DBG_EVENT_ATTACH_ERROR,
	DBG_EVENT_DETACH_ERROR,
	
	// Debugger events
	DBG_EVENT_ATTACH,
	DBG_EVENT_DETACH,
	DBG_EVENT_BREAKPOINTS_CHANGED,
	DBG_EVENT_BREAKPOINT_HIT,
	DBG_EVENT_UNCAUGHT_EXCEPTION
};

// Represents the response the user may give to an unhandled exception message.
enum ExceptionUserResponse
{
	EXCEPTION_RESPONSE_NONE,
	EXCEPTION_RESPONSE_CONTINUE,
	EXCEPTION_RESPONSE_ABORT
};

// The debugger class CrySearch uses to achieve several debugging actions.
class CryDebugger
{
private:
	Thread dbgThread;

	void ExceptionWatch();
	void HideDebuggerFromPeb() const;
	void DbgThread();
	
	const int FindBreakpointByPreviousInstruction(const SIZE_T address);
	
	virtual void HandleSoftwareBreakpoint(const DWORD threadId, const SIZE_T addr) = 0;
	virtual void HandleHardwareBreakpoint(const DWORD threadId, const SIZE_T addr) = 0;
	virtual void RemoveSingleStepFromBreakpoint(const DWORD threadId) = 0;
	virtual bool BreakpointRoutine(HardwareBreakpoint* pHwbp) const = 0;
	virtual const int CheckHardwareBreakpointRegisters(const DWORD threadId) const = 0;
	virtual DisasmLine GetDisasmLine(const SIZE_T address, bool prev) const = 0;
	
	typedef CryDebugger CLASSNAME;
protected:
	volatile bool mAttached;
	volatile bool shouldBreakLoop;
	bool isDetaching;
	const SettingsFile* mSettingsInstance;
	
	// Linked list with ownership property to take care of polymorphic breakpoint data structures.
	Array<DbgBreakpoint> mBreakpoints;
	
	void HandleMiscellaneousExceptions(const SIZE_T address, const LONG excCode, DWORD* dwContinueStatus);
	
	virtual void CreateStackSnapshot(DbgBreakpoint* pBp, const SIZE_T pEsp) = 0;
	virtual void ObtainCallStackTrace(DbgBreakpoint* pBp, void* const ctx) = 0;
public:
	CryDebugger();
	virtual ~CryDebugger();
	
	void Start();
	void Stop();
	
	bool SetHardwareBreakpoint(const Vector<Win32ThreadInformation>& threads, const SIZE_T address, const HWBP_SIZE size, const HWBP_TYPE type);
	bool SetBreakpoint(const SIZE_T address);
	
	bool DisableBreakpoint(const SIZE_T address);
	bool RemoveBreakpoint(const SIZE_T address);
	
	void ClearBreakpoints();
	int FindBreakpoint(const SIZE_T address) const;
	
	bool IsDebuggerAttached() const;
	const int GetBreakpointCount() const;
	
	const DbgBreakpoint& operator [] (const int x)
	{
		return this->mBreakpoints[x];
	}
	
	// If a breakpoint hit occured, the second parameter contains the index of the breakpoint in the array.
	// If an unhandled exception occured, the second parameter contains a pointer to the exception data.
	Callback2<DebugEvent, void*> DebuggerEvent;
};

// x86 specific debugger implementations.
class CryDebugger32 : public CryDebugger
{
private:
	virtual bool BreakpointRoutine(HardwareBreakpoint* pHwbp) const;
	virtual void HandleSoftwareBreakpoint(const DWORD threadId, const SIZE_T addr);
	virtual void HandleHardwareBreakpoint(const DWORD threadId, const SIZE_T addr);
	virtual void RemoveSingleStepFromBreakpoint(const DWORD threadId);
	virtual const int CheckHardwareBreakpointRegisters(const DWORD threadId) const;
	virtual DisasmLine GetDisasmLine(const SIZE_T address, bool prev) const;
	
	typedef CryDebugger32 CLASSNAME;
protected:
	virtual void CreateStackSnapshot(DbgBreakpoint* pBp, const SIZE_T pEsp);
	virtual void ObtainCallStackTrace(DbgBreakpoint* pBp, void* const ctx);
public:
	CryDebugger32();
	~CryDebugger32();
};

// x64 specific debugger implementations.
#ifdef _WIN64
	class CryDebugger64 : public CryDebugger
	{
	private:
		virtual bool BreakpointRoutine(HardwareBreakpoint* pHwbp) const;
		virtual void RemoveSingleStepFromBreakpoint(const DWORD threadId);
		virtual void HandleSoftwareBreakpoint(const DWORD threadId, const SIZE_T addr);
		virtual void HandleHardwareBreakpoint(const DWORD threadId, const SIZE_T addr);
		virtual const int CheckHardwareBreakpointRegisters(const DWORD threadId) const;
		virtual DisasmLine GetDisasmLine(const SIZE_T address, bool prev) const;
		
		typedef CryDebugger64 CLASSNAME;
	protected:
		virtual void CreateStackSnapshot(DbgBreakpoint* pBp, const SIZE_T pEsp);
		virtual void ObtainCallStackTrace(DbgBreakpoint* pBp, void* const ctx);
	public:
		CryDebugger64();
		~CryDebugger64();
	};
#endif

#endif
