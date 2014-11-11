#include "CryDebugger.h"
#include "GlobalDef.h"

#include "BeaEngine/include/BeaEngine.h"

#include <Psapi.h>
#include <VerRsrc.h>
#include <DbgHelp.h>

#pragma comment(lib, "DbgHelp.lib")

// WOW64 debugging definitions.
#define STATUS_WX86_UNSIMULATE				0x4000001C
#define STATUS_WX86_SINGLE_STEP 			0x4000001E
#define STATUS_WX86_BREAKPOINT				0x4000001F

// Hardware Breakpoint EFLAGS constants.
#define EFLAGS_CARRY						0x00000001
#define EFLAGS_PARITY						0x00000004
#define EFLAGS_ADJUST						0x00000010
#define EFLAGS_ZERO							0x00000040
#define EFLAGS_SIGN							0x00000080
#define EFLAGS_TRAP							0x00000100
#define EFLAGS_INTERRUPT_ENABLE				0x00000200
#define EFLAGS_DIRECTION					0x00000400
#define EFLAGS_OVERFLOW						0x00000800
#define EFLAGS_IOPL_0						0x00000000
#define EFLAGS_IOPL_1						0x00001000
#define EFLAGS_IOPL_2						0x00002000
#define EFLAGS_IOPL_3						0x00003000
#define EFLAGS_NESTED_TASK					0x00004000
#define EFLAGS_RESUME						0x00010000
#define EFLAGS_VIRTUAL_8086					0x00020000
#define EFLAGS_ALIGNMENT_CHECK				0x00040000
#define EFLAGS_VIRTUAL_INTERRUPT			0x00080000
#define EFLAGS_VIRTUAL_INTERRUPT_PENDING	0x00100000
#define EFLAGS_CPUID_AVAILABLE				0x00200000

// NtGlobalFlags constants in Process Environment Block.
#define FLG_STOP_ON_EXCEPTION				0x00000001
#define FLG_SHOW_LDR_SNAPS					0x00000002
#define FLG_DEBUG_INITIAL_COMMAND			0x00000004
#define FLG_STOP_ON_HUNG_GUI				0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK			0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK			0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS		0x00000040
#define FLG_HEAP_VALIDATE_ALL				0x00000080
#define FLG_POOL_ENABLE_TAIL_CHECK			0x00000100
#define FLG_POOL_ENABLE_FREE_CHECK			0x00000200
#define FLG_POOL_ENABLE_TAGGING				0x00000400
#define FLG_HEAP_ENABLE_TAGGING				0x00000800
#define FLG_USER_STACK_TRACE_DB				0x00001000
#define FLG_KERNEL_STACK_TRACE_DB			0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST		0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL			0x00008000
#define FLG_IGNORE_DEBUG_PRIV				0x00010000
#define FLG_ENABLE_CSRDEBUG					0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD		0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS		0x00080000
#define FLG_HEAP_ENABLE_CALL_TRACING		0x00100000
#define FLG_HEAP_DISABLE_COALESCING			0x00200000
#define FLG_VALID_BITS						0x003FFFFF
#define FLG_ENABLE_CLOSE_EXCEPTION			0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING		0x00800000
#define FLG_ENABLE_HANDLE_TYPE_TAGGING		0x01000000
#define FLG_HEAP_PAGE_ALLOCS				0x02000000
#define FLG_DEBUG_WINLOGON					0x04000000
#define FLG_ENABLE_DBGPRINT_BUFFERING		0x08000000
#define FLG_EARLY_CRITICAL_SECTION_EVT		0x10000000
#define FLG_DISABLE_DLL_VERIFICATION		0x80000000

// Anti-debugging flag check.
#define ANTI_DEBUG_PEB_FLAGS (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

// Vector of visible (loaded in current page) lines of disassembly.
extern Vector<DisasmLine> DisasmVisibleLines;

// ---------------------------------------------------------------------------------------------

// Debugger default constructor.
CryDebugger::CryDebugger()
{
	this->mSettingsInstance = SettingsFile::GetInstance();
	HANDLE loc = mMemoryScanner->GetHandle();
	
	// Initialize symbol handler for the process using configured symbol paths.
	const int pathCount = this->mSettingsInstance->GetSymbolPathCount();
	if (pathCount > 0)
	{
		// Add manually configured paths.
		String paths = this->mSettingsInstance->GetSymbolPath(0);
		for (int i = 1; i < pathCount; ++i)
		{
			paths += ";" + this->mSettingsInstance->GetSymbolPath(i);
		}
		
		// Add environmentally decided paths for possible invading.
		char envvar[MAX_PATH];
		envvar[0] = ';';
		GetEnvironmentVariable("_NT_SYMBOL_PATH", envvar + 1, MAX_PATH);
		paths += envvar;
		GetEnvironmentVariable("_NT_ALTERNATE_SYMBOL_PATH", envvar + 1, MAX_PATH);
		paths += envvar;
		
		// Initialize symbol handler with configured pathing.
		SymInitialize(loc, paths, this->mSettingsInstance->GetInvadeProcess() ? TRUE : FALSE);
	}
	else
	{
		// No symbol paths were configured, use Windows default ones.
		SymInitialize(loc, NULL, this->mSettingsInstance->GetInvadeProcess() ? TRUE : FALSE);
	}
	
	// Set options for the symbol handler.
	DWORD options = SymGetOptions();
	options |= SYMOPT_FAIL_CRITICAL_ERRORS;
	SymSetOptions(options);
	
	// If the process should not be invaded, the symbols for the executable module should be loaded manually.
	if (!this->mSettingsInstance->GetInvadeProcess())
	{
		// Retrieve the full path to the executable file of the process.
		char fn[MAX_PATH];
		GetModuleFileNameEx(mMemoryScanner->GetHandle(), NULL, fn, MAX_PATH);
		
		// By default, only load the executable module's symbols.
		const Win32ModuleInformation* exeMod;
		int retryCount = 0;
		
		// Try to get the first module but set a threshold for it to fail.
		while ((retryCount++ < 3) && !(exeMod = (mModuleManager->GetModuleCount() > 0 ? &(*mModuleManager)[0] : NULL)))
		{
			Sleep(25);
		}
		
		// If the module pointer is not null, lets load up the symbols.
		if (exeMod)
		{
			SymLoadModuleEx(mMemoryScanner->GetHandle(), NULL, fn, exeMod->ModuleName, exeMod->BaseAddress, (DWORD)exeMod->Length, NULL, 0);
		}
	}
	
	this->mAttached = false;
	this->isDetaching = false;
	this->shouldBreakLoop = false;
}

// Debugger default destructor. (Don't call this->Stop() in the destructor)
CryDebugger::~CryDebugger()
{
	// Cheecky exception is thrown when handle is invalid and debugger is attached...
	SymCleanup(mMemoryScanner->GetHandle());
}

// Returns whether the debugger is attached or not.
bool CryDebugger::IsDebuggerAttached() const
{
	return this->mAttached;
}

// Returns the amount of breakpoints currently set.
const int CryDebugger::GetBreakpointCount() const
{
	return this->mBreakpoints.GetCount();
}

// The debugger's thread that runs until it is detached.
void CryDebugger::DbgThread()
{
	// Attempt to attach the newly created thread as debugger to the process.
	this->mAttached = DebugActiveProcess(mMemoryScanner->GetProcessId());
	
	if (!this->mAttached)
	{
		// The debugger could not be attached, throw error.
		this->DebuggerEvent(DBG_EVENT_ATTACH_ERROR, NULL);
		return;
	}
	
	// Debugger was succesfully attached.
	this->DebuggerEvent(DBG_EVENT_ATTACH, NULL);
	
	// If the hide setting is enabled, execute PEB writing to hide debugger from process.
	if (this->mSettingsInstance->GetAttemptHideDebuggerFromPeb())
	{
		this->HideDebuggerFromPeb();
	}
	
	// Start debugger loop in this thread.
	this->ExceptionWatch();
}

// Starts the debugger on a seperate thread at the specified process handle and process ID.
void CryDebugger::Start()
{
	this->isDetaching = false;
	this->shouldBreakLoop = false;
	this->dbgThread.Run(THISBACK(DbgThread));
}

// Stops the debugger at the specified handle and process ID, clearing all breakpoints.
void CryDebugger::Stop()
{
	// remove all breakpoints before detaching from the process.
	this->ClearBreakpoints();
	this->shouldBreakLoop = true;
	
	// The finalization sequence of the debugger must wait for the debugger loop to close.
	this->dbgThread.Wait();

	this->DebuggerEvent(DBG_EVENT_DETACH, NULL);
}

// Set a hardware breakpoint on a series of threads.
// Returns true if hardware breakpoint was succesfully set or already set and false if invalid input was detected.
bool CryDebugger::SetHardwareBreakpoint(const Vector<Win32ThreadInformation>& threads, const SIZE_T address, const HWBP_SIZE size, const HWBP_TYPE type)
{
	// Inmediately return if no threads are specified or the address is invalid.
	if (!threads.GetCount() || !address)
	{
		return false;
	}
	
	bool error = false;
	const int count = threads.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const int threadId = threads[i].ThreadIdentifier;
		
		// If the hardware breakpoint was already set on this thread, return true.
		const int bpIndex = this->FindBreakpoint(address);
		if (bpIndex >= 0)
		{
			DbgBreakpoint* const hwbp = &this->mBreakpoints[bpIndex];
			if (hwbp->BpType == BPTYPE_HARDWARE)
			{
				HardwareBreakpoint* const castedHwbp = static_cast<HardwareBreakpoint*>(hwbp);
				if (castedHwbp->IsSet(threadId))
				{
					// The breakpoint was already set on this thread.
					continue;
				}
				else
				{
					// Add this thread to the list associated to the breakpoint.
					castedHwbp->ThreadId.Add(threadId);
					if (!BreakpointRoutine(castedHwbp))
					{
						error = true;
					}
					
					this->DebuggerEvent(DBG_EVENT_BREAKPOINTS_CHANGED, NULL);
					continue;
				}
			}
		}
	
		// Create breakpoint in local collection for administration.
		HardwareBreakpoint& hwbp = (HardwareBreakpoint&)this->mBreakpoints.Add(new HardwareBreakpoint());
		hwbp.BpType = BPTYPE_HARDWARE;
		hwbp.ThreadId.Add(threadId);
		hwbp.HitCount = 0;
		hwbp.Address = address;
		hwbp.Size = size;
		hwbp.Type = type;
		hwbp.MustSet = true;
		hwbp.PreviousInstructionAddress = 0;
		hwbp.Disabled = FALSE;
		
		// Set old instruction to 0 to indicate that it is a hardware breakpoint.
		hwbp.OldInstruction = 0;
		
		// Set breakpoint into thread.
		if (!BreakpointRoutine(&hwbp))
		{
			error = true;
		}
	}
	
	this->DebuggerEvent(DBG_EVENT_BREAKPOINTS_CHANGED, NULL);
	return !error;
}

// Set a regular software breakpoint on an address containing executable code.
bool CryDebugger::SetBreakpoint(const SIZE_T address)
{
	// Check whether there already is a breakpoint set on this address.
	if (this->FindBreakpoint(address) >= 0)
	{
		return true;
	}
	
	DbgBreakpoint& bp = this->mBreakpoints.Add(new DbgBreakpoint());
	bp.BpType = BPTYPE_SOFTWARE;
	bp.HitCount = 0;
	bp.Address = address;
	bp.Disabled = FALSE;
	
	// Read out current byte.
	if (!CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, &bp.OldInstruction, sizeof(Byte), NULL))
	{
		return false;
	}
	
	// Write INT3 instruction to the specified address.
	const Byte _int3 = 0xCC;
	if (!CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, &_int3, sizeof(Byte), NULL))
	{
		return false;
	}
	
	// Flush instruction cache to apply instruction to executable code.
	FlushInstructionCache(mMemoryScanner->GetHandle(), (void*)address, sizeof(Byte));
	
	// Add breakpoint to local breakpoint list and signal user interface.
	this->DebuggerEvent(DBG_EVENT_BREAKPOINTS_CHANGED, NULL);
	
	return true;
}

// Disable a breakpoint set in the process.
bool CryDebugger::DisableBreakpoint(const SIZE_T address)
{
	bool error = false;
	
	// Check whether the breakpoint actually exists on this address.
	const int pos = this->FindBreakpoint(address);
	if (pos < 0)
	{
		return true;
	}
	
	DbgBreakpoint* const bp = &this->mBreakpoints[pos];
	if (bp->BpType == BPTYPE_HARDWARE)
	{
		// Attempt to remove breakpoint as being a hardware breakpoint.
		HardwareBreakpoint* const hwbp = static_cast<HardwareBreakpoint*>(bp);
		hwbp->MustSet = false;
		
		for (int i = 0; i < hwbp->ThreadId.GetCount(); ++i)
		{
			if (!BreakpointRoutine(hwbp))
			{
				error = true;
			}
		}
	}
	else
	{
		// Write the old instruction back to the address.
		if (!CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, &bp->OldInstruction, sizeof(Byte), NULL))
		{
			return false;
		}
		
		// Flush instruction cache to apply instruction to executable code.
		FlushInstructionCache(mMemoryScanner->GetHandle(), (void*)address, sizeof(Byte));
	}
	
	// Set disabled flag for user interface.
	bp->Disabled = TRUE;

	// Only trigger the UI events in case the removal is just a single breakpoint. If the debugger is cleaning up before detaching, nothing has to be done.
	if (!isDetaching)
	{
		this->DebuggerEvent(DBG_EVENT_BREAKPOINTS_CHANGED, NULL);
	}

	return !error;
}

// Remove a breakpoint from the process.
bool CryDebugger::RemoveBreakpoint(const SIZE_T address)
{
	bool error = false;
	
	// Check whether the breakpoint actually exists on this address.
	const int pos = this->FindBreakpoint(address);
	if (pos < 0)
	{
		return true;
	}
	
	DbgBreakpoint* const bp = &this->mBreakpoints[pos];
	if (bp->BpType == BPTYPE_HARDWARE)
	{
		// Attempt to remove breakpoint as being a hardware breakpoint.
		HardwareBreakpoint* const hwbp = static_cast<HardwareBreakpoint*>(bp);
		hwbp->MustSet = false;
		
		for (int i = 0; i < hwbp->ThreadId.GetCount(); ++i)
		{
			if (!BreakpointRoutine(hwbp))
			{
				error = true;
			}
		}
	}
	else
	{
		// Write the old instruction back to the address.
		if (!CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), (void*)address, &bp->OldInstruction, sizeof(Byte), NULL))
		{
			return false;
		}
		
		// Flush instruction cache to apply instruction to executable code.
		FlushInstructionCache(mMemoryScanner->GetHandle(), (void*)address, sizeof(Byte));
	}
	
	// Free context memory if set.
	bp->BreakpointSnapshot.Release();

	// Remove the breakpoint from the list.
	this->mBreakpoints.Remove(pos);

	// Only trigger the UI events in case the removal is just a single breakpoint. If the debugger is cleaning up before detaching, nothing has to be done.
	if (!isDetaching)
	{
		this->DebuggerEvent(DBG_EVENT_BREAKPOINTS_CHANGED, NULL);
	}

	return !error;
}

// Checks whether a software breakpoint already exists. Hardware breakpoints are different, because they can be on the same address but for multiple threads.
int CryDebugger::FindBreakpoint(const SIZE_T address) const
{
	const int persistentCount = this->mBreakpoints.GetCount();
	for (int i = 0; i < persistentCount; ++i)
	{
		// Check whether the address is equal, but also whether the old instruction byte is set. If it is not set, we have a hardware breakpoint.
		if (this->mBreakpoints[i].Address == address)
		{
			return i;
		}
	}
	
	return -1;
}

// Checks whether a breakpoint matches a previously trapped instruction. This function is needed to reveal single stepped exceptions from data breakpoints.
const int CryDebugger::FindBreakpointByPreviousInstruction(const SIZE_T address)
{
	for (int i = 0; i < this->mBreakpoints.GetCount(); i++)
	{
		if (this->mBreakpoints[i].BpType == BPTYPE_HARDWARE)
		{
			if (static_cast<HardwareBreakpoint*>(&this->mBreakpoints[i])->PreviousInstructionAddress == address)
			{
				return i;
			}
		}
	}
	
	return -1;
}

// Clears all breakpoints from the list of breakpoints and removes them from the target process.
void CryDebugger::ClearBreakpoints()
{
	this->isDetaching = true;
	
	// Remove all breakpoints from the list.
	for (int i = 0; i < this->mBreakpoints.GetCount(); i++)
	{
		this->RemoveBreakpoint(this->mBreakpoints[i].Address);
	}
	
	this->isDetaching = false;
}

// Handles any exception that occured in the opened process except for breakpoints.
void CryDebugger::HandleMiscellaneousExceptions(const SIZE_T address, const LONG excCode, DWORD* dwContinueStatus)
{
	// Create exception data structure to pass to the user interface.
	UnhandledExceptionData* const param = new UnhandledExceptionData;
	param->ExceptionAddress = address;
	param->ExceptionCode = excCode;
	
	// Execute debugger event in user interface.
	this->DebuggerEvent(DBG_EVENT_UNCAUGHT_EXCEPTION, param);
	
	// Wait for the user to response to the exception message.
	param->UserResponse = EXCEPTION_RESPONSE_NONE;
	while (param->UserResponse == EXCEPTION_RESPONSE_NONE)
	{
		Sleep(50);
	}
	
	// Response has been given, handle accordingly.
	if (param->UserResponse == DBG_EXCEPTION_NOT_HANDLED)
	{
		// The user chose to abort the process and close the debugger.
		*dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
		this->Stop();
	}
}

// The debugger loop that is ran by the debugger thread and will keep that thread alive until detach.
void CryDebugger::ExceptionWatch()
{
	// Tell the Win32 debugger to not kill the attached process if CrySearch crashes or is closed.
	DebugSetProcessKillOnExit(FALSE);
	
	// Prepare for the debugging loop.
	DWORD dwContinueStatus = DBG_CONTINUE;
	DEBUG_EVENT DebugEv;
	
	while (1)
	{
		// Check for a debug event. 250 ms because I need to be able to close the loop.
		WaitForDebugEvent(&DebugEv, 250);
		
		// Debug event occured, see which one and act appropriately.
		if (DebugEv.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			SIZE_T excAddress = (SIZE_T)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
			
			// Parse exception code.
			if (DebugEv.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
#ifdef _WIN64
				|| DebugEv.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT	
#endif
)
			{
				if (this->mBreakpoints.GetCount() > 0)
				{
					this->HandleSoftwareBreakpoint(DebugEv.dwThreadId, excAddress);
					
					// Set the line of disassembly that triggered the breakpoint.
					this->mBreakpoints[this->FindBreakpoint(excAddress)].BreakpointSnapshot.DisassemblyAccessLine = this->GetDisasmLine(excAddress, false);
				}
			}
			else if (DebugEv.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
#ifdef _WIN64
					|| DebugEv.u.Exception.ExceptionRecord.ExceptionCode == STATUS_WX86_SINGLE_STEP
#endif
)
			{
				const int bpCount = this->mBreakpoints.GetCount();
				if (bpCount > 0)
				{
					DisasmLine excPrevLine = this->GetDisasmLine(excAddress, true);
					DisasmLine excLine = this->GetDisasmLine(excAddress, false);
					
					// Get breakpoint at the previous instruction reflected against the current exception address.
					int bp = this->FindBreakpoint(excPrevLine.VirtualAddress);
					
					if (bp == -1 || bp > bpCount)
					{
						// If a breakpoint was not found on the previous instruction, try to find it on the current (HWBP).
						// This condition is for the first chance hit of a hardware breakpoint.
						bp = this->FindBreakpoint(excAddress);
						
						// If the breakpoint was found, the line of accessing disassembly is found too.
						if (bp >= 0)
						{
							this->mBreakpoints[bp].BreakpointSnapshot.DisassemblyAccessLine = excLine;	
						}
					}

					if (bp == -1 || bp > bpCount)
					{
						// Breakpoint was not found on current address as HWBP, so it may be a data breakpoint.
						if ((bp = this->CheckHardwareBreakpointRegisters(DebugEv.dwThreadId)) != -1)
						{
							excAddress = excPrevLine.VirtualAddress;
							
							// If the breakpoint was found, the line of accessing disassembly is found too.
							if (bp >= 0)
							{
								this->mBreakpoints[bp].BreakpointSnapshot.DisassemblyAccessLine = excPrevLine;	
							}
						}
					}
					
					if (bp == -1 || bp > bpCount)
					{
						// Data breakpoints can have their single steps occur too. This means the original instruction is disasmIndex - 2.
						bp = this->FindBreakpointByPreviousInstruction(this->GetDisasmLine(excPrevLine.VirtualAddress, true).VirtualAddress);
					}
						
					if (bp >= 0 && bpCount > 0)
					{
						if (this->mBreakpoints[bp].BpType == BPTYPE_HARDWARE)
						{
							HardwareBreakpoint* const pHwbp = static_cast<HardwareBreakpoint*>(&this->mBreakpoints[bp]);

							if (this->mBreakpoints[bp].ProcessorTrapFlag == 0xFF)
							{
								// Reset trap flag and reinstate breakpoint to resume execution safely.
								this->RemoveSingleStepFromBreakpoint(DebugEv.dwThreadId);
								this->BreakpointRoutine(pHwbp);
								pHwbp->ProcessorTrapFlag = 0;
								pHwbp->PreviousInstructionAddress = 0;
							}
							else
							{
								// Hardware breakpoint is hit, take care of it.
								pHwbp->PreviousInstructionAddress = excAddress;
								this->HandleHardwareBreakpoint(DebugEv.dwThreadId, pHwbp->Address);
							}
						}
						else
						{
							// Single step caused by software breakpoint being previously hit.
							// Write back INT3 to the original spot of the breakpoint.
							const Byte int3Bp = 0xCC;
							CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), (void*)this->mBreakpoints[bp].Address, &int3Bp, sizeof(Byte), NULL);

							// Remove single step flag from the thread context.
							this->RemoveSingleStepFromBreakpoint(DebugEv.dwThreadId);
						}
					}
				}
			}
			else
			{
				// If the user wanted to, catch exception.
				if (this->mSettingsInstance->GetCatchAllExceptions())
				{
					// Another exception occured, but CrySearch is not able to handle anything other than breakpoints. Report it to the user.
					this->HandleMiscellaneousExceptions((SIZE_T)DebugEv.u.Exception.ExceptionRecord.ExceptionAddress, DebugEv.u.Exception.ExceptionRecord.ExceptionCode, &dwContinueStatus);
				}
				else
				{
					// Exceptions are set to not being caught by the debugger. Let the process crash.
					dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
			}
		}
		
		// Previous debug event was handled succesfully, continue to watch for new events.
		ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);

		// When the timeout of WaitForDebugEvent elapses and no debug event occured, the previous debug event in local memory is re-executed
		// because the struct is not cleared by the function itself. This results in a lot of trouble, therefore I clean the struct myself every time.
		memset(&DebugEv, 0, sizeof(DEBUG_EVENT));
		
		// If the loop should break, quit it.
		if (this->shouldBreakLoop)
		{
			if (this->mAttached = !DebugActiveProcessStop(mMemoryScanner->GetProcessId()))
			{
				this->DebuggerEvent(DBG_EVENT_DETACH_ERROR, NULL);
			}
			else
			{
				this->DebuggerEvent(DBG_EVENT_DETACH, NULL);
			}
			
			break;
		}
	}
}

// ---------------------------------------------------------------------------------------------

// 32 bits debugger constructor.
CryDebugger32::CryDebugger32()
{
	
}

// 32 bits debugger destructor.
CryDebugger32::~CryDebugger32()
{
	
}

// Retrieves an instruction line from the disassembly.
DisasmLine CryDebugger32::GetDisasmLine(const SIZE_T address, bool prev) const
{
	return prev ? DisasmGetPreviousLine(address, ARCH_X86) : DisasmGetLine(address, ARCH_X86);
}

// Attempts hiding the debugger presence from the process. This way, IsDebuggerPresent would return FALSE.
void CryDebugger32::HideDebuggerFromPeb() const
{
	// Get address of PEB in remote process.
	PPEB32 remotePeb = (PPEB32)mPeInstance->GetPebAddress();

	// Reset the debug flag.
	// Poke the address of the flag with a 0 value.
	BYTE pResetted = 0x0;
	CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), &remotePeb->BeingDebugged, &pResetted, sizeof(BYTE), NULL);
	
	// When a debugger is attached, the NtGlobalFlag field in PEB may contain 0x70 flags. These flags mean
	// FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
	// They are not always applied when a debugger is attached but to be sure, we should remove them.
	ULONG pNtGlobalFlag;
	CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), &remotePeb->NtGlobalFlag, &pNtGlobalFlag, sizeof(ULONG), NULL);
	
	// Remove the flags and write them back.
	pNtGlobalFlag &= ~ANTI_DEBUG_PEB_FLAGS;
	CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), &remotePeb->NtGlobalFlag, &pNtGlobalFlag, sizeof(ULONG), NULL);
}

// Creates a snapshot of the stack pointed to by the second parameter: ESP.
void CryDebugger32::CreateStackSnapshot(DbgBreakpoint* pBp, const SIZE_T pEsp)
{
	pBp->BreakpointSnapshot.StackView.Clear();
	
	Byte stack[1024];
	CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)pEsp, stack, 1024, NULL);
	DWORD stackPtr = (DWORD)stack;
	const DWORD endAddress = (DWORD)pEsp + this->mSettingsInstance->GetStackSnapshotLimit();
	
	for (DWORD addr = (DWORD)pEsp; addr < endAddress; addr += sizeof(DWORD), stackPtr += sizeof(DWORD))
	{
		StackViewData& newEntry = pBp->BreakpointSnapshot.StackView.Add();
		newEntry.StackAddress = addr;
		newEntry.StackValue = *(SIZE_T*)stackPtr;
	}	
}

// Retrieves hardware breakpoint from instruction that accessed data that the breakpoint was set on.
const int CryDebugger32::CheckHardwareBreakpointRegisters(const DWORD threadId) const
{
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
	
#ifdef _WIN64
	WOW64_CONTEXT ctx;
	memset(&ctx, 0, sizeof(WOW64_CONTEXT));
	ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
	Wow64GetThreadContext(hThread, &ctx);

#else
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &ctx);
#endif	

	CloseHandle(hThread);
	
	// Bit-wise check which debug register triggered the exception.
	if (ctx.Dr6 & (1 << 0))
	{
		return this->FindBreakpoint(ctx.Dr0);
	}
	else if (ctx.Dr6 & (1 << 1))
	{
		return this->FindBreakpoint(ctx.Dr1);
	}
	else if (ctx.Dr6 & (1 << 2))
	{
		return this->FindBreakpoint(ctx.Dr2);
	}
	else if (ctx.Dr6 & (1 << 3))
	{
		return this->FindBreakpoint(ctx.Dr3);
	}
	
	return -1;
}

// Obtains the stack trace for a hit breakpoint and puts it into the last parameter.
void CryDebugger32::ObtainCallStackTrace(DbgBreakpoint* pBp, void* const ctx)
{
	if (!pBp || !ctx)
	{
		return;
	}
	
	// Create call stack.
	ConstructStackTrace(mMemoryScanner->GetHandle(), IMAGE_FILE_MACHINE_I386, ctx, pBp->BreakpointSnapshot.CallStackView);
}

// Hardware breakpoint routine
bool CryDebugger32::BreakpointRoutine(HardwareBreakpoint* pHwbp) const
{
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, pHwbp->ThreadId[pHwbp->ThreadId.GetCount() - 1]);
	
#ifdef _WIN64
	// Suspend thread in which to set breakpoint.
	if (!pHwbp->ProcessorTrapFlag && Wow64SuspendThread(hThread) == (DWORD)-1)
	{
		return false;
	}
	
	WOW64_CONTEXT ct;
	memset(&ct, 0, sizeof(WOW64_CONTEXT));
	ct.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_DEBUG_REGISTERS;
	
	if (!Wow64GetThreadContext(hThread, &ct))
	{
		ResumeThread(hThread);
		return false;
	}
#else
	if (!pHwbp->ProcessorTrapFlag && SuspendThread(hThread) == (DWORD)-1)
	{
		return false;
	}

	CONTEXT ct;
	memset(&ct, 0, sizeof(CONTEXT));
	ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	
	if (!GetThreadContext(hThread, &ct))
	{
		ResumeThread(hThread);
		return false;
	}
#endif

	if (pHwbp->MustSet)
	{
		unsigned long m_index = 0;
	
		// Find available debug register.
		for (; m_index < 4; ++m_index)
	    {
#ifdef _WIN64
	    	if ((ct.Dr7 & (1i64 << (m_index * 2))) == 0)
#else
	    	if ((ct.Dr7 & (1 << (m_index * 2))) == 0)
#endif
	    	{
	    		break;
	    	}
	    }
	    
	    // If this condition is true, all breakpoints are used, meaning the new breakpoint cannot be set.
	    if (m_index >= 4)
	    {
	        return false;
	    }
	    
	    // Set address in selected debug register.
#ifdef _WIN64
		switch (m_index)
	    {
	        case 0:
	        	ct.Dr0 = (DWORD)pHwbp->Address;
	        	pHwbp->DebugRegister = 0;
	        	break;
	        case 1:
	        	ct.Dr1 = (DWORD)pHwbp->Address;
	        	pHwbp->DebugRegister = 1;
	        	break;
	        case 2:
	        	ct.Dr2 = (DWORD)pHwbp->Address;
	        	pHwbp->DebugRegister = 2;
	        	break;
	        case 3:
	        	ct.Dr3 = (DWORD)pHwbp->Address;
	        	pHwbp->DebugRegister = 3;
	        	break;
	    }
	    
	    CrySetBits((DWORD_PTR*)&ct.Dr7, 16 + (m_index * 4), 2, pHwbp->Type);
	    CrySetBits((DWORD_PTR*)&ct.Dr7, 18 + (m_index * 4), 2, pHwbp->Size);
	    CrySetBits((DWORD_PTR*)&ct.Dr7, m_index * 2, 1, 1);
#else
	    switch (m_index)
	    {
		    case 0:
	        	ct.Dr0 = pHwbp->Address;
	        	pHwbp->DebugRegister = 0;
	        	break;
	        case 1:
	        	ct.Dr1 = pHwbp->Address;
	        	pHwbp->DebugRegister = 1;
	        	break;
	        case 2:
	        	ct.Dr2 = pHwbp->Address;
	        	pHwbp->DebugRegister = 2;
	        	break;
	        case 3:
	        	ct.Dr3 = pHwbp->Address;
	        	pHwbp->DebugRegister = 3;
	        	break;
		}
		
		CrySetBits(&ct.Dr7, 16 + (m_index * 4), 2, pHwbp->Type);
	    CrySetBits(&ct.Dr7, 18 + (m_index * 4), 2, pHwbp->Size);
	    CrySetBits(&ct.Dr7, m_index * 2, 1, 1);
#endif
	}
	else
	{
		switch (pHwbp->DebugRegister)
		{
			case 0:
				ct.Dr0 = 0;
				break;
			case 1:
				ct.Dr1 = 0;
				break;
			case 2:
				ct.Dr2 = 0;
				break;
			case 3:
				ct.Dr3 = 0;
				break;
		}
		
#ifdef _WIN64
		CrySetBits((DWORD_PTR*)&ct.Dr7, pHwbp->DebugRegister * 2, 1, 0);
#else
		CrySetBits(&ct.Dr7, pHwbp->DebugRegister * 2, 1, 0);
#endif
		pHwbp->DebugRegister = 0;
	}
	
#ifdef _WIN64

	ct.Dr6 = 0;
	
	// Prepare context struct and set it into the threads context.
	if (!Wow64SetThreadContext(hThread, &ct))
	{
		ResumeThread(hThread);
		return false;
	}
#else
	// Prepare context struct and set it into the threads context.
	if (!SetThreadContext(hThread, &ct))
	{
		ResumeThread(hThread);
		return false;
	}
#endif
	
	// Everything succeeded until now. resume thread and return.
	if (!pHwbp->ProcessorTrapFlag)
	{
		ResumeThread(hThread);
	}
	
	CloseHandle(hThread);
	return true;
}

// After an INT3 breakpoint has been hit, the debugger sets a single step flag to make it possible
// to reinstate the breakpoint afterwards. This function removes the single step flag.
void CryDebugger32::RemoveSingleStepFromBreakpoint(const DWORD threadId)
{
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);

#ifdef _WIN64
	WOW64_CONTEXT ct;
	memset(&ct, 0, sizeof(WOW64_CONTEXT));
	ct.ContextFlags = WOW64_CONTEXT_CONTROL;
	Wow64GetThreadContext(hThread, &ct);
#else
	CONTEXT ct;
	memset(&ct, 0, sizeof(CONTEXT));
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
#endif
	
	ct.EFlags &= ~EFLAGS_TRAP;

#ifdef _WIN64
	Wow64SetThreadContext(hThread, &ct);
#else
	SetThreadContext(hThread, &ct);
#endif

	CloseHandle(hThread);
}

// Takes care of a software breakpoint the moment it is hit.
void CryDebugger32::HandleSoftwareBreakpoint(const DWORD threadId, const SIZE_T addr)
{
	const int bpIndex = this->FindBreakpoint(addr);
	if (bpIndex == -1)
	{
		return;
	}

	DbgBreakpoint& bp = this->mBreakpoints[bpIndex];
	++bp.HitCount;
	
	// Create snapshot of registers to pass to the user interface.
#ifdef _WIN64
	WOW64_CONTEXT ctx;
	memset(&ctx, 0, sizeof(WOW64_CONTEXT));
	ctx.ContextFlags = WOW64_CONTEXT_FULL;
#else
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_FULL;
#endif	
	
	// Retrieve thread context.
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);

#ifdef _WIN64
	Wow64GetThreadContext(hThread, &ctx);
#else
	GetThreadContext(hThread, &ctx);
#endif
	
	// Rewind EIP and restore original instruction.
	SIZE_T bpAddr = --ctx.Eip;
	CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), (void*)bpAddr, &bp.OldInstruction, sizeof(Byte), NULL);
	
	// Flush instruction cache to effectively apply original instruction again.
	FlushInstructionCache(mMemoryScanner->GetHandle(), (void*)bpAddr, sizeof(Byte));

	// Set single step flags and put back thread context.
	ctx.EFlags |= EFLAGS_TRAP;
	
	// Free context memory if set.
	bp.BreakpointSnapshot.Release();

#ifdef _WIN64
	Wow64SetThreadContext(hThread, &ctx);	
	bp.BreakpointSnapshot.ThreadContextContainer = new CryThreadContext<WOW64_CONTEXT>();
	memcpy(&((CryThreadContext<WOW64_CONTEXT>*)bp.BreakpointSnapshot.ThreadContextContainer)->ThreadContext, &ctx, sizeof(WOW64_CONTEXT));
#else
	SetThreadContext(hThread, &ctx);
	bp.BreakpointSnapshot.ThreadContextContainer = new CryThreadContext<CONTEXT>();
	memcpy(&((CryThreadContext<CONTEXT>*)bp.BreakpointSnapshot.ThreadContextContainer)->ThreadContext, &ctx, sizeof(CONTEXT));
#endif
	
	CloseHandle(hThread);
	
	// Set hit associated data for the breakpoint.
	this->CreateStackSnapshot(&bp, ctx.Esp);
	this->ObtainCallStackTrace(&bp, &ctx);
	bp.BreakpointSnapshot.RegisterFieldCount = REGISTERCOUNT_86;
	
	// Send trigger to user interface.
	this->DebuggerEvent(DBG_EVENT_BREAKPOINT_HIT, (void*)bpIndex);
}

// Takes care of a hardware breakpoint the moment it is hit.
void CryDebugger32::HandleHardwareBreakpoint(const DWORD threadId, const SIZE_T addr)
{
	const int bpIndex = this->FindBreakpoint(addr);
	HardwareBreakpoint& hwbp = (HardwareBreakpoint&)this->mBreakpoints[bpIndex];
	++hwbp.HitCount;
	
	// Create snapshot of registers to pass to the user interface.
#ifdef _WIN64
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, threadId);
	WOW64_CONTEXT ctx;
	memset(&ctx, 0, sizeof(WOW64_CONTEXT));
	ctx.ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_DEBUG_REGISTERS;
	Wow64GetThreadContext(hThread, &ctx);
#else
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
	CONTEXT ctx;
	memset(&ctx, 0, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &ctx);
#endif

	// Set single step flags, remove processor break and put back thread context.
	ctx.EFlags |= EFLAGS_TRAP;
	ctx.Dr6 = 0;
	
	switch (hwbp.DebugRegister)
	{
		case 0:
			ctx.Dr0 = 0;
			break;
		case 1:
			ctx.Dr1 = 0;
			break;
		case 2:
			ctx.Dr2 = 0;
			break;
		case 3:
			ctx.Dr3 = 0;
			break;
	}
	
	// Free context memory if set.
	hwbp.BreakpointSnapshot.Release();
	
#ifdef _WIN64
	CrySetBits((DWORD_PTR*)&ctx.Dr7, hwbp.DebugRegister * 2, 1, 0);
	ctx.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_DEBUG_REGISTERS;
	Wow64SetThreadContext(hThread, &ctx);
	hwbp.BreakpointSnapshot.ThreadContextContainer = new CryThreadContext<WOW64_CONTEXT>();
	memcpy(&((CryThreadContext<WOW64_CONTEXT>*)hwbp.BreakpointSnapshot.ThreadContextContainer)->ThreadContext, &ctx, sizeof(WOW64_CONTEXT));	
#else
	CrySetBits(&ctx.Dr7, hwbp.DebugRegister * 2, 1, 0);
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
	SetThreadContext(hThread, &ctx);
	hwbp.BreakpointSnapshot.ThreadContextContainer = new CryThreadContext<CONTEXT>();
	memcpy(&((CryThreadContext<CONTEXT>*)hwbp.BreakpointSnapshot.ThreadContextContainer)->ThreadContext, &ctx, sizeof(CONTEXT));
#endif
	
	// Set the old instruction field to 0xFF in order to indicate that this hwbp's next hit is a single step trap.
	hwbp.ProcessorTrapFlag = 0xFF;
	
	CloseHandle(hThread);
	
	// Set hit associated data for the breakpoint.
	this->CreateStackSnapshot(&hwbp, ctx.Esp);
	this->ObtainCallStackTrace(&hwbp, &ctx);
	hwbp.BreakpointSnapshot.RegisterFieldCount = REGISTERCOUNT_86;
	
	// Send trigger to user interface.
	this->DebuggerEvent(DBG_EVENT_BREAKPOINT_HIT, (void*)bpIndex);
}

// ---------------------------------------------------------------------------------------------

#ifdef _WIN64
	// 64 bits debugger default constructor.
	CryDebugger64::CryDebugger64()
	{
		
	}
	
	// 64 bits debugger default destructor.
	CryDebugger64::~CryDebugger64()
	{
		
	}
	
	// Retrieves an instruction line from the disassembly.
	DisasmLine CryDebugger64::GetDisasmLine(const SIZE_T address, bool prev) const
	{
		return prev ? DisasmGetPreviousLine(address, ARCH_X64) : DisasmGetLine(address, ARCH_X64);
	}	
	
	// Attempts hiding the debugger presence from the process. This way, IsDebuggerPresent would return FALSE.
	void CryDebugger64::HideDebuggerFromPeb() const
	{
		// Get address of PEB in remote process.
		PPEB remotePeb = (PPEB)mPeInstance->GetPebAddress();
	
		// Reset the debug flag.
		// Poke the address of the flag with a 0 value.
		BYTE pResetted = 0x0;
		CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), &remotePeb->BeingDebugged, &pResetted, sizeof(BYTE), NULL);
		
		// When a debugger is attached, the NtGlobalFlag field in PEB may contain 0x70 flags. These flags mean
		// FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
		// They are not always applied when a debugger is attached but to be sure, we should remove them.
		ULONG pNtGlobalFlag;
		CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), &remotePeb->NtGlobalFlag, &pNtGlobalFlag, sizeof(ULONG), NULL);
		
		// Remove the flags and write them back.
		pNtGlobalFlag &= ~ANTI_DEBUG_PEB_FLAGS;
		CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), &remotePeb->NtGlobalFlag, &pNtGlobalFlag, sizeof(ULONG), NULL);
	}
	
	// Creates a snapshot of the stack pointed to by the second parameter: ESP.
	void CryDebugger64::CreateStackSnapshot(DbgBreakpoint* pBp, const SIZE_T pEsp)
	{
		pBp->BreakpointSnapshot.StackView.Clear();
		
		Byte stack[1024];
		CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)pEsp, stack, 1024, NULL);
		SIZE_T stackPtr = (SIZE_T)stack;
		const SIZE_T endAddress = (SIZE_T)pEsp + this->mSettingsInstance->GetStackSnapshotLimit();
		
		for (SIZE_T addr = (SIZE_T)pEsp; addr < endAddress; addr += sizeof(SIZE_T), stackPtr += sizeof(SIZE_T))
		{
			StackViewData& newEntry = pBp->BreakpointSnapshot.StackView.Add();
			newEntry.StackAddress = addr;
			newEntry.StackValue = *(SIZE_T*)stackPtr;
		}	
	}
	
	// Retrieves hardware breakpoint from instruction that accessed data that the breakpoint was set on.
	const int CryDebugger64::CheckHardwareBreakpointRegisters(const DWORD threadId) const
	{
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
		
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		memset(ctx, 0, sizeof(CONTEXT));

		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(hThread, ctx);
		CloseHandle(hThread);
		
		int retIndex = -1;

		// Check which debug register triggered the exception.
		if (ctx->Dr6 & (1 << 0))
		{
			retIndex = this->FindBreakpoint(ctx->Dr0);
		}
		else if (ctx->Dr6 & (1 << 1))
		{
			retIndex = this->FindBreakpoint(ctx->Dr1);
		}
		else if (ctx->Dr6 & (1 << 2))
		{
			retIndex = this->FindBreakpoint(ctx->Dr2);
		}
		else if (ctx->Dr6 & (1 << 3))
		{
			retIndex = this->FindBreakpoint(ctx->Dr3);
		}
		
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		return retIndex;
	}
	
	// After an INT3 breakpoint has been hit, the debugger sets a single step flag to make it possible
	// to reinstate the breakpoint afterwards. This function removes the single step flag.
	void CryDebugger64::RemoveSingleStepFromBreakpoint(const DWORD threadId)
	{
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
	
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		memset(ctx, 0, sizeof(CONTEXT));
		ctx->ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, ctx);
		
		// Remove the single step flag from the thread context and put it back.
		ctx->EFlags &= ~EFLAGS_TRAP;
		SetThreadContext(hThread, ctx);
		
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		CloseHandle(hThread);
	}
	
	// Takes care of a software breakpoint the moment it is hit.
	void CryDebugger64::HandleSoftwareBreakpoint(const DWORD threadId, const SIZE_T addr)
	{
		const int bpIndex = this->FindBreakpoint(addr);
		if (bpIndex == -1)
		{
			return;
		}

		DbgBreakpoint& bp = this->mBreakpoints[bpIndex];
		++bp.HitCount;
		
		// Allocate context structure on the heap and align the pointer to an 8 byte boundary.
		// x64 needs this in order to succeed. If this is not done, the error is ERROR_NOACCESS.
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		memset(ctx, 0, sizeof(CONTEXT));
		
		ctx->ContextFlags = CONTEXT_FULL;
		
		// Retrieve thread context.
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
		GetThreadContext(hThread, ctx);
		
		// Rewind EIP and restore original instruction.
		SIZE_T bpAddr = --ctx->Rip;
		CrySearchRoutines.CryWriteMemoryRoutine(mMemoryScanner->GetHandle(), (void*)bpAddr, &bp.OldInstruction, sizeof(Byte), NULL);
		
			// Flush instruction cache to effectively apply original instruction again.
		FlushInstructionCache(mMemoryScanner->GetHandle(), (void*)bpAddr, sizeof(Byte));

		// Set single step flags and put back thread context.
		ctx->EFlags |= EFLAGS_TRAP;
		SetThreadContext(hThread, ctx);
		
		CloseHandle(hThread);

		// Free context memory if set.
		bp.BreakpointSnapshot.Release();

		// Set hit associated data for the breakpoint.
		this->CreateStackSnapshot(&bp, ctx->Rsp);
		this->ObtainCallStackTrace(&bp, ctx);
		bp.BreakpointSnapshot.ThreadContextContainer = new CryThreadContext<CONTEXT>();
		memcpy(&((CryThreadContext<CONTEXT>*)bp.BreakpointSnapshot.ThreadContextContainer)->ThreadContext, ctx, sizeof(CONTEXT));
		bp.BreakpointSnapshot.RegisterFieldCount = REGISTERCOUNT_64;
		
		VirtualFree(ctxBase, 0, MEM_RELEASE);
			
		// Send trigger to user interface.
		this->DebuggerEvent(DBG_EVENT_BREAKPOINT_HIT, (void*)bpIndex);
	}
	
	// Takes care of a hardware breakpoint the moment it is hit.
	void CryDebugger64::HandleHardwareBreakpoint(const DWORD threadId, const SIZE_T addr)
	{
		const int bpIndex = this->FindBreakpoint(addr);
		HardwareBreakpoint& hwbp = (HardwareBreakpoint&)this->mBreakpoints[bpIndex];
		++hwbp.HitCount;
		
		// Create snapshot of registers to pass to the user interface.
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
		
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT const ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		memset(ctx, 0, sizeof(CONTEXT));
		
		// Retrieve the thread context of the breakpoint thread into a local variable.
		ctx->ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(hThread, ctx);
		
		// Set single step flags, remove processor break and put back thread context.
		ctx->EFlags |= EFLAGS_TRAP;
		ctx->Dr6 = 0;
		
		switch (hwbp.DebugRegister)
		{
			case 0:
				ctx->Dr0 = 0;
				break;
			case 1:
				ctx->Dr1 = 0;
				break;
			case 2:
				ctx->Dr2 = 0;
				break;
			case 3:
				ctx->Dr3 = 0;
				break;
		}
		
		CrySetBits(&ctx->Dr7, hwbp.DebugRegister * 2, 1, 0);
		SetThreadContext(hThread, ctx);
		
		// Set the old instruction field to 0xFF in order to indicate that this hwbp's next hit is a single step trap.
		hwbp.ProcessorTrapFlag = 0xFF;
		
		// Free context memory if set.
		hwbp.BreakpointSnapshot.Release();
		
		// Set hit associated data for the breakpoint.
		this->CreateStackSnapshot(&hwbp, ctx->Rsp);
		this->ObtainCallStackTrace(&hwbp, ctx);
		hwbp.BreakpointSnapshot.ThreadContextContainer = new CryThreadContext<CONTEXT>();
		memcpy(&((CryThreadContext<CONTEXT>*)hwbp.BreakpointSnapshot.ThreadContextContainer)->ThreadContext, ctx, sizeof(CONTEXT));
		hwbp.BreakpointSnapshot.RegisterFieldCount = REGISTERCOUNT_64;
		
		// Free used resources.
		CloseHandle(hThread);
		VirtualFree(ctxBase, 0, MEM_RELEASE);
		
		// Send trigger to user interface.
		this->DebuggerEvent(DBG_EVENT_BREAKPOINT_HIT, (void*)bpIndex);
	}
	
	// Hardware breakpoint routine
	bool CryDebugger64::BreakpointRoutine(HardwareBreakpoint* pHwbp) const
	{
		HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, pHwbp->ThreadId[pHwbp->ThreadId.GetCount() - 1]);
		
		// Prepare thread context struct and retrieve thread context into it.
		if (!pHwbp->ProcessorTrapFlag && SuspendThread(hThread) == (DWORD)-1)
		{
			return false;
		}
	
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT const ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		memset(ctx, 0, sizeof(CONTEXT));

		ctx->ContextFlags = CONTEXT_DEBUG_REGISTERS;
		
		if (!GetThreadContext(hThread, ctx))
		{
			VirtualFree(ctxBase, 0, MEM_RELEASE);
			ResumeThread(hThread);
			return false;
		}
 
	    if (pHwbp->MustSet)
	    {
	        unsigned long m_index = 0;

			// Find available debug register.
			for (; m_index < 4; ++m_index)
		    {
		    	if ((ctx->Dr7 & (1i64 << (m_index * 2))) == 0)
		    	{
		    		break;
		    	}
		    }
		    
		    // If this condition is true, all breakpoints are used, meaning the new breakpoint cannot be set.
		    if (m_index >= 4)
		    {
				VirtualFree(ctxBase, 0, MEM_RELEASE);
		        return false;
		    }
		    
	        // Set address in selected debug register.
		    switch (m_index)
		    {
		        case 0:
		        	ctx->Dr0 = pHwbp->Address;
		        	pHwbp->DebugRegister = 0;
		        	break;
		        case 1:
		        	ctx->Dr1 = pHwbp->Address;
		        	pHwbp->DebugRegister = 1;
		        	break;
		        case 2:
		        	ctx->Dr2 = pHwbp->Address;
		        	pHwbp->DebugRegister = 2;
		        	break;
		        case 3:
		        	ctx->Dr3 = pHwbp->Address;
		        	pHwbp->DebugRegister = 3;
		        	break;
		    }
		    
			CrySetBits(&ctx->Dr7, 16 + (m_index * 4), 2, pHwbp->Type);
		    CrySetBits(&ctx->Dr7, 18 + (m_index * 4), 2, pHwbp->Size);
		    CrySetBits(&ctx->Dr7, m_index * 2, 1, 1);
	    }
	    else
		{
			switch (pHwbp->DebugRegister)
			{
				case 0:
					ctx->Dr0 = 0;
					break;
				case 1:
					ctx->Dr1 = 0;
					break;
				case 2:
					ctx->Dr2 = 0;
					break;
				case 3:
					ctx->Dr3 = 0;
					break;
			}
			
			CrySetBits((DWORD_PTR*)&ctx->Dr7, pHwbp->DebugRegister * 2, 1, 0);
			pHwbp->DebugRegister = 0;
		}	    
		
		ctx->Dr6 = 0;
		
		// Prepare context struct and set it into the threads context.
		if (!SetThreadContext(hThread, ctx))
		{
			VirtualFree(ctxBase, 0, MEM_RELEASE);
			ResumeThread(hThread);
			return false;
		}
		
		VirtualFree(ctxBase, 0, MEM_RELEASE);

		// Everything succeeded until now. resume thread and return.
		if (!pHwbp->ProcessorTrapFlag)
		{
			ResumeThread(hThread);
		}
		
		CloseHandle(hThread);
		return true;
	}
	
	// Obtains the stack trace for a hit breakpoint and puts it into the last parameter.
	void CryDebugger64::ObtainCallStackTrace(DbgBreakpoint* pBp, void* const ctx)
	{
		if (!pBp || !ctx)
		{
			return;
		}
		
		// Create call stack.
		ConstructStackTrace(mMemoryScanner->GetHandle(), IMAGE_FILE_MACHINE_AMD64, ctx, pBp->BreakpointSnapshot.CallStackView);
	}
#endif