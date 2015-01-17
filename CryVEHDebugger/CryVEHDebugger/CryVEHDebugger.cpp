#include "CryVEHDebug.h"

CryVEHDebugger::CryVEHDebugger()
{
	this->mIsRunning = false;
}

CryVEHDebugger::~CryVEHDebugger()
{

}

// Starts the debugger, allowing exceptions to be caught.
void CryVEHDebugger::Start()
{
	this->mIsRunning = true;
}

// Stops the debugger. This results in exceptions not being caught anymore.
void CryVEHDebugger::Stop()
{
	this->mIsRunning = false;
}

// --------------------------------------------------------------------------------------------------------

// Attempts to add a software breakpoint to the process. Returns true if a breakpoint already exists at
// the specified address and if the function succeeds. Returns false otherwise.
const bool CryVEHDebugger::AddSoftwareBreakpoint(const SIZE_T address)
{
	if (this->FindBreakpoint(address) >= 0)
	{
		return true;
	}

	// Create new breakpoint structure.
	CryBreakpoint newSoftwareBp;
	newSoftwareBp.Address = address;
	newSoftwareBp.OldInstruction = *(BYTE*)address;
	this->breakpointList.push_back(newSoftwareBp);

	// Write INT3 instruction to the specified address.
	*(BYTE*)address = 0xCC;

	// Flush instruction cache to apply instruction to executable code.
	FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(BYTE));

	return true;
}

// Attempts to add a hardware breakpoint to the process. Returns true if a breakpoint already exists at
// the specified address and if the function succeeds. Returns false otherwise.
const bool CryVEHDebugger::AddHardwareBreakpoint(const SIZE_T address, CryHwbpSize size, CryHwbpType type)
{
	if (this->FindBreakpoint(address) >= 0)
	{
		return true;
	}

	// Create new breakpoint structure.
	CryBreakpoint newHardwareBp;
	newHardwareBp.Address = address;
	newHardwareBp.BreakpointType = HardwareBreakpoint;
	newHardwareBp.MustSetHardware = true;
	newHardwareBp.HardwareSize = size;
	newHardwareBp.HardwareType = type;
	this->breakpointList.push_back(newHardwareBp);

	// Get all threads in the process.
	std::vector<DWORD> threadIds;
	EnumerateThreads(threadIds);

	const int count = threadIds.size();
	for (int i = 0; i < count; ++i)
	{
		// Execute the breakpoint routine for each enumerated thread.
		BreakpointRoutine(&newHardwareBp, threadIds[i]);
	}

	return true;
}

// Attempts to disable a breakpoint. This removes the breakpoint from the process but does not remove 
// the breakpoint from the debugger administration. Returns true if succeeded or false otherwise.
const bool CryVEHDebugger::DisableBreakpoint(const SIZE_T address)
{
	const int pos = this->FindBreakpoint(address);
	if (pos == -1)
	{
		return true;
	}

	CryBreakpoint* bp = &this->breakpointList[pos];
	if (bp->BreakpointType == HardwareBreakpoint)
	{
		bp->MustSetHardware = false;
		const int threadcount = bp->AffectedThreads.size();
		for (int i = 0; i < threadcount; ++i)
		{
			// Execute the breakpoint routine for each enumerated thread.
			BreakpointRoutine(bp, bp->AffectedThreads[i]);
		}
	}
	else
	{
		// Restore old instruction and flush instruction cache.
		*(BYTE*)address = bp->OldInstruction;
		FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(BYTE));
	}

	bp->Disabled = true;

	return true;
}

// Attempts to remove a breakpoint from the process. Returns true if the function succeeded
// or false otherwise.
const bool CryVEHDebugger::RemoveBreakpoint(const SIZE_T address)
{
	const int pos = this->FindBreakpoint(address);
	if (pos == -1)
	{
		return true;
	}

	CryBreakpoint* bp = &this->breakpointList[pos];
	if (bp->BreakpointType == HardwareBreakpoint)
	{
		bp->MustSetHardware = false;
		const int threadcount = bp->AffectedThreads.size();
		for (int i = 0; i < threadcount; ++i)
		{
			// Execute the breakpoint routine for each enumerated thread.
			BreakpointRoutine(bp, bp->AffectedThreads[i]);
		}
	}
	else
	{
		// Restore old instruction and flush instruction cache.
		*(BYTE*)address = bp->OldInstruction;
		FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(BYTE));
	}

	// Remove the breakpoint structure from the list.
	this->breakpointList.erase(this->breakpointList.begin() + pos);

	return true;
}

// --------------------------------------------------------------------------------------------------------

// Gets whether the debugger is running or not.
const bool CryVEHDebugger::IsRunning() const
{
	return this->mIsRunning;
}

// Returns the amount of breakpoints currently set.
const int CryVEHDebugger::GetBreakpointCount() const
{
	return this->breakpointList.size();
}

// Finds a breakpoint by address in the breakpoint list. Returns the index of the breakpoint
// in the list if it is found and -1 if it is not found.
const int CryVEHDebugger::FindBreakpoint(const SIZE_T address) const
{
	const int bpsize = this->breakpointList.size();
	for (int i = 0; i < bpsize; ++i)
	{
		if (this->breakpointList[i].Address == address)
		{
			return i;
		}
	}

	return -1;
}