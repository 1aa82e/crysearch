#include "CrySearchWindowManager.h"
#include "CryDebuggerWindow.h"
#include "ImlProvider.h"
#include "FrontendGlobalDef.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"
#include "CrashHandler.h"

// Master index indicates which hit breakpoint is currently selected.
int BreakpointMasterIndex = 0;

// ---------------------------------------------------------------------------------------------

// Gets the string representation of the address of a breakpoint.
String GetBreakpointAddress(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return FormatHexadecimalIntSpecial((int)(*mDebugger)[index].Address);
	}
	else
	{
		return FormatInt64HexUpper((*mDebugger)[index].Address);
	}
#else
	return FormatHexadecimalIntSpecial((int)(*mDebugger)[index].Address);
#endif
}

// Gets the number of hits for a specified breakpoint.
String GetBreakpointHitCount(const int index)
{
	return FormatInt((*mDebugger)[index].HitCount);
}

// Gets the string representation of an address in the stack snapshot.
String GetStackViewAddress(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return FormatHexadecimalIntSpecial((int)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Wow64Context.Esp + (index * sizeof(DWORD)));
	}
	else
	{
		return FormatInt64HexUpper((*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Context64.Rsp + (index * sizeof(DWORD)));
	}
#else
	return FormatHexadecimalIntSpecial((*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Context86.Esp + (index * sizeof(DWORD)));
#endif
}

// Gets the string representation of the value at a specific place in the stack memory.
String GetStackViewValue(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		const SIZE_T esp = (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Wow64Context.Esp;
		int value;
		mMemoryScanner->Peek(esp + (index * sizeof(DWORD)), sizeof(DWORD), &value);
		return FormatHexadecimalIntSpecial(value);
	}
	else
	{
		const SIZE_T esp = (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Context64.Rsp;
		__int64 value;
		mMemoryScanner->Peek(esp + (index * sizeof(SIZE_T)), sizeof(SIZE_T), &value);
		return FormatInt64HexUpper(value);
	}
#else
	const SIZE_T esp = (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Context86.Esp;
	int value;
	mMemoryScanner->Peek(esp + (index * sizeof(DWORD)), sizeof(DWORD), &value);
	return FormatHexadecimalIntSpecial(value);
#endif
}

// Gets the function call, possibly resolved using debug symbols.
String GetCallStackFunctionCall(const int index)
{
	// Due to synchronization problems that occur very rarely, we need to work around a possible
	// race condition. To just ignore values that create a race condition, we fix this problem.
	const Vector<DWORD64>& csView = (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.CallStackView;
	if (index >= 0 && index < csView.GetCount())
	{
		const DWORD64 address = (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.CallStackView[index];
		const Win32ModuleInformation* mod = NULL;
		if (mod = mModuleManager->GetModuleFromContainedAddress((SIZE_T)address))
		{
			// Find the module that contains this address.
			String modName = mModuleManager->GetModuleFilename(mod->BaseAddress);
			char symbolName[MAX_PATH];
			if (GetSingleSymbolName(mMemoryScanner->GetHandle(), (SIZE_T)address, symbolName, MAX_PATH))
			{
				// Using debug symbols, we found the actual name of the function. Great!
				return Format("%s!%s", modName, symbolName);
			}
			else
			{
				// We know in which module the function resides, but we don't know the name.
				return Format("%s!%llX", modName, (LONG_PTR)address);
			}
		}
		else
		{
			// We couldn't locate the module containing this address.
			return FormatInt64HexUpper((LONG_PTR)address);
		}
	}
	else
	{
		return "";
	}
}

// ---------------------------------------------------------------------------------------------

// The CryDebuggerWindow default constructor.
CryDebuggerWindow::CryDebuggerWindow()
{
	this->AddFrame(mToolStrip);
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	*this
		<< this->mGlobalSplitter.Horz(this->mLeftSplitter.Horz(this->mBreakpointsHitList.SizePos(), this->mDebuggerHitView.SizePos())
			, this->mRightSplitter.Vert(this->mCallStackView.SizePos(), this->mStackView.SizePos()))
	;
	
	this->mBreakpointsHitList.CryAddRowNumColumn("Address", 60).SetConvert(Single<IndexBasedValueConvert<GetBreakpointAddress>>());
	this->mBreakpointsHitList.CryAddRowNumColumn("Count", 40).SetConvert(Single<IndexBasedValueConvert<GetBreakpointHitCount>>());
	this->mBreakpointsHitList.WhenBar = THISBACK(BreakpointListRightClick);
	
	this->mStackView.CryAddRowNumColumn("Address").SetConvert(Single<IndexBasedValueConvert<GetStackViewAddress>>());
	this->mStackView.CryAddRowNumColumn("Value").SetConvert(Single<IndexBasedValueConvert<GetStackViewValue>>());
	this->mStackView.WhenBar = THISBACK(StackViewRightClick);
	
	this->mCallStackView.CryAddRowNumColumn("Function Call").SetConvert(Single<IndexBasedValueConvert<GetCallStackFunctionCall>>());
	this->mCallStackView.WhenBar = THISBACK(CallStackListRightClick);
	
	this->mBreakpointsHitList.WhenSel = THISBACK(BreakpointSelectionChanged);
	this->mDebuggerHitView.SetTooltip("Click to follow in disassembler.");
}

// The CryDebuggerWindow default destructor.
CryDebuggerWindow::~CryDebuggerWindow()
{
	if (mDebugger)
	{
		mDebugger->SetDebuggerEventLockProcessed();
	}
}

// Populates the toolstrip.
void CryDebuggerWindow::ToolStrip(Bar& pBar)
{
	const bool elegible = mDebugger && mDebugger->GetBreakpointCount() > 0;
	pBar.Add(elegible, "Clear Breakpoints", CrySearchIml::ClearBreakpointsSmall(), THISBACK(DebuggerClearBreakpoints));
}

// Initializes the debugger window.
void CryDebuggerWindow::Initialize()
{
	mDebugger->DebuggerEventOccured = THISBACK(DebuggerEventOccured);
}

// Executed when the user changes the selection of a breakpoint.
void CryDebuggerWindow::BreakpointSelectionChanged()
{
	BreakpointMasterIndex = this->mBreakpointsHitList.GetCursor();
	if (BreakpointMasterIndex >= 0 && BreakpointMasterIndex < mDebugger->GetBreakpointCount())
	{
		const DbgBreakpoint& bp = (*mDebugger)[(int)BreakpointMasterIndex];
		this->mDebuggerHitView.SetInstructionString(bp.BreakpointSnapshot.DisassemblyAccessLine);
		this->mDebuggerHitView.SetRegisterCount(bp.BreakpointSnapshot.RegisterFieldCount);
		this->DynamicCreateStackView();
		this->mCallStackView.SetVirtualCount(bp.BreakpointSnapshot.CallStackView.GetCount());
	}
	
	// Refresh the toolstrip.
	this->mToolStrip.Set(THISBACK(ToolStrip));
}

// Executed when the user right clicks the stack view.
void CryDebuggerWindow::StackViewRightClick(Bar& pBar)
{
	if (mDebugger->IsDebuggerAttached())
	{
		const int cursor = this->mStackView.GetCursor();
		if (cursor >= 0 && mDebugger->GetBreakpointCount() > 0)
		{
			pBar.Add("Copy Value", CtrlImg::copy(), THISBACK(CopyStackViewValue));
		}
	}
}

// Executed when the user right clicks the breakpoint list.
void CryDebuggerWindow::BreakpointListRightClick(Bar& pBar)
{
	if (mDebugger->IsDebuggerAttached())
	{
		const int cursor = this->mBreakpointsHitList.GetCursor();
		if (cursor >= 0 && mDebugger->GetBreakpointCount() > 0)
		{
			pBar.Add(!(*mDebugger)[cursor].Disabled, "Disable", THISBACK(DisableBreakpointButtonClicked));
			pBar.Add("Remove Breakpoint", CrySearchIml::DeleteButton(), THISBACK(RemoveBreakpointButtonClicked));
		}
	}
}

// Executed when the user right clicks the call stack.
void CryDebuggerWindow::CallStackListRightClick(Bar& pBar)
{
	if (mDebugger->IsDebuggerAttached())
	{
		const int cursor = this->mCallStackView.GetCursor();
		if (cursor >= 0 && mDebugger->GetBreakpointCount() > 0)
		{
			pBar.Add("Go to Disassembly", CrySearchIml::DisassemblyIcon(), THISBACK(FollowStackTraceInDisassembler));
		}
	}
}

// Copies the value of the selected stack view row.
void CryDebuggerWindow::CopyStackViewValue()
{
	const int cursor = this->mStackView.GetCursor();
	if (cursor > 0 && this->mStackView.GetCount())
	{
		WriteClipboardText(GetStackViewValue(cursor));
	}
}

// Jumps to disassembly view, selecting the address selected in the stack trace.
void CryDebuggerWindow::FollowStackTraceInDisassembler()
{
	mCrySearchWindowManager->GetDisasmWindow()->MoveToAddress((SIZE_T)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.CallStackView[this->mCallStackView.GetCursor()]);
	mCrySearchWindowManager->GetParentWindow()->SetActiveTabWindow("Disassembly");
}

// Disables the selected breakpoint.
void CryDebuggerWindow::DisableBreakpointButtonClicked()
{
	const int cursor = this->mBreakpointsHitList.GetCursor();
	mDebugger->DisableBreakpoint((*mDebugger)[cursor].Address);
}

// Removes the selected breakpoint.
void CryDebuggerWindow::RemoveBreakpointButtonClicked()
{
	const int cursor = this->mBreakpointsHitList.GetCursor();
	this->Cleanup();
	mDebugger->RemoveBreakpoint((*mDebugger)[cursor].Address);
}

// Releases all used resources in this window, making it ready to close.
void CryDebuggerWindow::Cleanup()
{
	this->mBreakpointsHitList.Clear();
	this->mDebuggerHitView.ClearInstructionString();
	this->mDebuggerHitView.SetRegisterCount(0);
	this->mStackView.SetVirtualCount(0);
	this->mCallStackView.SetVirtualCount(0);
}

// Executed when the debugger subsystem returned an error.
void CryDebuggerWindow::DebuggerEventOccured(DebugEvent event, void* param)
{
	PostCallback(THISBACK2(DebuggerEventOccuredThreadsafe, event, param));
}

// Creates the stack view when a breakpoint is hit.
void CryDebuggerWindow::DynamicCreateStackView()
{
	if ((*mDebugger)[(int)BreakpointMasterIndex].HitCount)
	{
#ifdef _WIN64
		if (mMemoryScanner->IsX86Process())
		{
			this->mStackView.SetVirtualCount(SettingsFile::GetInstance()->GetStackSnapshotLimit() / sizeof(DWORD));
		}
		else
		{
			this->mStackView.SetVirtualCount(SettingsFile::GetInstance()->GetStackSnapshotLimit() / sizeof(SIZE_T));
		}
#else
		this->mStackView.SetVirtualCount(SettingsFile::GetInstance()->GetStackSnapshotLimit() / sizeof(DWORD));
#endif
	}
}

// Thread-safe dispatch function for the error event.
void CryDebuggerWindow::DebuggerEventOccuredThreadsafe(DebugEvent event, void* param)
{
	switch (event)
	{
		case DBG_EVENT_ATTACH:
			// Send debugger attached event to loaded plugins.
			mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_DEBUGGER_ATTACHED, NULL);
			break;
		case DBG_EVENT_DETACH: // debugger was succesfully detached.
			this->mBreakpointsHitList.Clear();
			this->mDebuggerHitView.ClearInstructionString();
			this->mDebuggerHitView.SetRegisterCount(0);
			this->mStackView.Clear();
			this->mCallStackView.Clear();
			
			// Send debugger detached event to loaded plugins.
			mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_DEBUGGER_DETACHED, NULL);
			break;
		case DBG_EVENT_ATTACH_ERROR: // another debugger was probably already attached, error is thrown.
			Prompt("Fatal Error", CtrlImg::error(), "Failed to attach the debugger. Another debugger may already have been attached or it is attempting to attach the debugger to itself.", "OK");
			this->DebugErrorOccured();
			break;
		case DBG_EVENT_DETACH_ERROR: // the debugger was not succesfully detached. This is a rare matter but I still catch it.
			Prompt("Fatal Error", CtrlImg::error(), "The debugger could not be succesfully detached!", "OK");
			break;
		case DBG_EVENT_BREAKPOINTS_CHANGED:
			// Something changed in the breakpoint list, causing the user interface to need a refresh.
			this->HandleBreakpointChanged((int)param);
			break;
		case DBG_EVENT_UNCAUGHT_EXCEPTION:
			// the debugger caught an exception in the opened process that cannot be handled.
			this->HandleUnhandledException(reinterpret_cast<UnhandledExceptionData*>(param));
			
			// Free the memory pointed to by the parameter pointer.
			delete param;
			break;
		case DBG_EVENT_BREAKPOINT_HIT:
			// Update the snapshot lists if the current breakpoint is selected. Prevents crashing with master index mismatch.
			if ((int)param == BreakpointMasterIndex && (int)param < mDebugger->GetBreakpointCount())
			{
				const DbgBreakpoint& bp = (*mDebugger)[(int)param];
				this->mDebuggerHitView.SetInstructionString(bp.BreakpointSnapshot.DisassemblyAccessLine);
				this->mDebuggerHitView.SetRegisterCount(bp.BreakpointSnapshot.RegisterFieldCount);
				this->DynamicCreateStackView();
				this->mCallStackView.SetVirtualCount(bp.BreakpointSnapshot.CallStackView.GetCount());
			}
			
			// Hit count of breakpoint should have changed, so refresh the breakpoint list too.
			this->mBreakpointsHitList.SetVirtualCount(mDebugger->GetBreakpointCount());
			mDebugger->SetDebuggerEventLockProcessed();
			break;
	}
	
	// Refresh the toolstrip.
	this->mToolStrip.Set(THISBACK(ToolStrip));
}

// Handles the user interface refreshing for changed breakpoint status.
void CryDebuggerWindow::HandleBreakpointChanged(const int bpIndex)
{
	if (bpIndex == BREAKPOINT_SET_FAILED)
	{
		Prompt("Fatal Error", CtrlImg::error(), "Failed to set the breakpoint! Are there currently four hardware breakpoints set?", "OK");
	}
	else
	{
		// We need to check whether the debugger is still attached here, because we will get
		// a race condition if it is not.
		if (mDebugger)
		{
			const int bpCount = mDebugger->GetBreakpointCount();
			if (bpCount > 0 && bpIndex < bpCount)
			{
				BreakpointMasterIndex = bpIndex;
				const DbgBreakpoint& bp = (*mDebugger)[bpIndex];
				
				// Update the snapshot lists.
				this->mDebuggerHitView.SetInstructionString(bp.BreakpointSnapshot.DisassemblyAccessLine);
				this->mDebuggerHitView.SetRegisterCount(bp.BreakpointSnapshot.RegisterFieldCount);
				this->DynamicCreateStackView();
				this->mCallStackView.SetVirtualCount(bp.BreakpointSnapshot.CallStackView.GetCount());
				
				// Recheck all breakpoints and reset display colors. This is the most stable way.
				for (int i = 0; i < bpCount; ++i)
				{
					this->mBreakpointsHitList.SetRowDisplay(i, (*mDebugger)[i].Disabled ? RedDisplayDrawInstance : StdDisplay());
				}
				
				// Set breakpoint count and redraw user interface. It seems that empty an data set keeps the UI from redrawing.
				this->mBreakpointsHitList.SetVirtualCount(bpCount);
			}
			else
			{
				// If the last breakpoint was removed, clear every list in the window.
				this->mDebuggerHitView.ClearInstructionString();
				this->mDebuggerHitView.SetRegisterCount(0);
				this->mStackView.Clear();
				this->mCallStackView.Clear();
				this->mBreakpointsHitList.Clear();
			}
		}
	}
}

// Handles an unhandled exception in the opened process.
void CryDebuggerWindow::HandleUnhandledException(UnhandledExceptionData* param)
{
	int result = Prompt("Unhandled Exception", CtrlImg::exclamation(), Format("An unhandled exception occured in the opened process:&&Exception: %s&Address: %llX", ParseExceptionCode(param->ExceptionCode), (LONG_PTR)param->ExceptionAddress), "Ignore", "Abort");
	if (result == 1)
	{
		// The ignore button was clicked. Let the exception slip through and continue debugging.
		param->UserResponse = EXCEPTION_RESPONSE_CONTINUE;
	}
	else if (result == 0)
	{
		// The abort button was clicked. Exit the debugger and let the exception drop into its own exception handlers.
		param->UserResponse = EXCEPTION_RESPONSE_ABORT;
		
		// If the debugger didn't already clean up the application because of the crash, do it anyway.
		if (mDebugger)
		{
			mDebugger->Stop();
		}

		// Throw error occured event, to close debugger window.
		this->DebugErrorOccured();
	}
}

// Clears all breakpoints in the list.
void CryDebuggerWindow::DebuggerClearBreakpoints()
{
	if (Prompt("Are you sure?", CtrlImg::exclamation(), "Are you sure you want to remove all breakpoints?", "Yes", "No"))
	{
		mDebugger->ClearBreakpoints();
		this->HandleBreakpointChanged(0);
	}
}

// Updates the toolbar inside this lower pane window instance.
void CryDebuggerWindow::UpdateToolbar()
{
	this->mToolStrip.Set(THISBACK(ToolStrip));
}