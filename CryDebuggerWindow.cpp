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

String GetBreakpointAddress(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return Format("%lX", (LONG_PTR)(*mDebugger)[index].Address);
	}
	else
	{
		return Format("%llX", (LONG_PTR)(*mDebugger)[index].Address);
	}
#else
	return Format("%lX", (LONG_PTR)(*mDebugger)[index].Address);
#endif
}

String GetBreakpointHitCount(const int index)
{
	return Format("%i", (*mDebugger)[index].HitCount);
}

String GetStackViewAddress(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return Format("%lX", (LONG_PTR)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.StackView[index].StackAddress);
	}
	else
	{
		return Format("%llX", (LONG_PTR)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.StackView[index].StackAddress);
	}
#else
	return Format("%lX", (LONG_PTR)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.StackView[index].StackAddress);
#endif
}

String GetStackViewValue(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return Format("%lX", (LONG_PTR)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.StackView[index].StackValue);
	}
	else
	{
		return Format("%llX", (LONG_PTR)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.StackView[index].StackValue);
	}
#else
	return Format("%lX", (LONG_PTR)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.StackView[index].StackValue);
#endif
}

String GetCallStackFunctionCall(const int index)
{
	return (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.CallStackView[index].StringRepresentation;
}

// ---------------------------------------------------------------------------------------------

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
	
	this->mCallStackView.CryAddRowNumColumn("Function Call").SetConvert(Single<IndexBasedValueConvert<GetCallStackFunctionCall>>());
	this->mCallStackView.WhenBar = THISBACK(CallStackListRightClick);
	
	this->mBreakpointsHitList.WhenSel = THISBACK(BreakpointSelectionChanged);
	this->mDebuggerHitView.SetTooltip("Click to follow in disassembler.");
}

CryDebuggerWindow::~CryDebuggerWindow()
{
	
}

void CryDebuggerWindow::ToolStrip(Bar& pBar)
{
	const bool elegible = mDebugger && mDebugger->GetBreakpointCount() > 0;
	pBar.Add(elegible, "Clear Breakpoints", CrySearchIml::ClearBreakpointsSmall(), THISBACK(DebuggerClearBreakpoints));
}

void CryDebuggerWindow::BreakpointSelectionChanged()
{
	BreakpointMasterIndex = this->mBreakpointsHitList.GetCursor();
	if (BreakpointMasterIndex >= 0)
	{
		const DbgBreakpoint& bp = (*mDebugger)[(int)BreakpointMasterIndex];
		this->mDebuggerHitView.SetInstructionString(bp.BreakpointSnapshot.DisassemblyAccessLine);
		this->mDebuggerHitView.SetRegisterCount(bp.BreakpointSnapshot.RegisterFieldCount);
		this->mStackView.SetVirtualCount(bp.BreakpointSnapshot.StackView.GetCount());
		this->mCallStackView.SetVirtualCount(bp.BreakpointSnapshot.CallStackView.GetCount());
	}
	
	// Refresh the toolstrip.
	this->mToolStrip.Set(THISBACK(ToolStrip));	
}

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

void CryDebuggerWindow::FollowStackTraceInDisassembler()
{
	const Win32StackTraceEntry& entry = (*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.CallStackView[this->mCallStackView.GetCursor()];
	mCrySearchWindowManager->GetDisasmWindow()->MoveToAddress(entry.Address);
	mCrySearchWindowManager->GetParentWindow()->SetActiveTabWindow("Disassembly");
}

void CryDebuggerWindow::DisableBreakpointButtonClicked()
{
	const int cursor = this->mBreakpointsHitList.GetCursor();
	mDebugger->DisableBreakpoint((*mDebugger)[cursor].Address);
	this->mBreakpointsHitList.SetRowDisplay(cursor, RedDisplayDrawInstance);
	this->mBreakpointsHitList.SetVirtualCount(mDebugger->GetBreakpointCount());
}

void CryDebuggerWindow::RemoveBreakpointButtonClicked()
{
	const int cursor = this->mBreakpointsHitList.GetCursor();
	mDebugger->RemoveBreakpoint((*mDebugger)[cursor].Address);
	this->mBreakpointsHitList.SetVirtualCount(mDebugger->GetBreakpointCount());
}

void CryDebuggerWindow::Initialize()
{
	mDebugger->DebuggerEvent = THISBACK(CryDebuggerEventOccured);
}

void CryDebuggerWindow::Cleanup()
{
	this->mDebuggerHitView.ClearInstructionString();
	this->mDebuggerHitView.SetRegisterCount(0);
	this->mStackView.SetVirtualCount(0);
	this->mCallStackView.SetVirtualCount(0);
}

void CryDebuggerWindow::CryDebuggerEventOccured(DebugEvent event, void* param)
{
	PostCallback(THISBACK2(CryDebuggerEventOccuredThreadSafe, event, param));
}

// Beware: the parameter: 'param' may not be NULL if the 'event' parameter is DBG_EVENT_UNCAUGHT_EXCEPTION!
void CryDebuggerWindow::CryDebuggerEventOccuredThreadSafe(DebugEvent event, void* param)
{
	switch (event)
	{
		case DBG_EVENT_ATTACH:
			// Send debugger attached event to loaded plugins.
			mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_DEBUGGER_ATTACHED, NULL);			
			break;
		case DBG_EVENT_DETACH: // debugger was succesfully detached.
			this->mBreakpointsHitList.SetVirtualCount(0);
			this->mDebuggerHitView.ClearInstructionString();
			this->mDebuggerHitView.SetRegisterCount(0);
			this->mStackView.SetVirtualCount(0);
			this->mCallStackView.SetVirtualCount(0);
			
			// Send debugger detached event to loaded plugins.
			mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_DEBUGGER_DETACHED, NULL);
			break;
		case DBG_EVENT_ATTACH_ERROR: // another debugger was probably already attached, error is thrown.
			Prompt("Debug Error", CtrlImg::error(), "Failed to attach the debugger. Another debugger may already have been attached or it is attempting to attach the debugger to itself.", "OK");
			this->DebugErrorOccured();
			break;
		case DBG_EVENT_DETACH_ERROR: // the debugger was not succesfully detached. This is a rare matter but I still catch it.
			Prompt("Debug Error", CtrlImg::error(), "The debugger could not be succesfully detached!", "OK");
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
				this->mStackView.SetVirtualCount(bp.BreakpointSnapshot.StackView.GetCount());
				this->mCallStackView.SetVirtualCount(bp.BreakpointSnapshot.CallStackView.GetCount());
			}
			
			// Hit count of breakpoint should have changed, so refresh the breakpoint list too.
			this->mBreakpointsHitList.SetVirtualCount(mDebugger->GetBreakpointCount());
			break;
	}
	
	// Refresh the toolstrip.
	this->mToolStrip.Set(THISBACK(ToolStrip));
}

// Handles the user interface refreshing for changed breakpoint status.
void CryDebuggerWindow::HandleBreakpointChanged(const int bpIndex)
{
	const int bpCount = mDebugger->GetBreakpointCount();
	if (bpCount > 0)
	{
		BreakpointMasterIndex = 0;
		const DbgBreakpoint& bp = (*mDebugger)[bpIndex];
		
		// Update the snapshot lists.
		this->mDebuggerHitView.SetInstructionString(bp.BreakpointSnapshot.DisassemblyAccessLine);
		this->mDebuggerHitView.SetRegisterCount(bp.BreakpointSnapshot.RegisterFieldCount);
		this->mStackView.SetVirtualCount(bp.BreakpointSnapshot.StackView.GetCount());
		this->mCallStackView.SetVirtualCount(bp.BreakpointSnapshot.CallStackView.GetCount());
	}
	else
	{
		// If the last breakpoint was removed, clear every list in the window.
		this->mDebuggerHitView.ClearInstructionString();
		this->mDebuggerHitView.SetRegisterCount(0);
		this->mStackView.Clear();
		this->mCallStackView.Clear();				
	}
	
	// Recheck all breakpoints and reset display colors. This is the most stable way.
	for (int i = 0; i < bpCount; ++i)
	{
		this->mBreakpointsHitList.SetRowDisplay(i, (*mDebugger)[i].Disabled ? RedDisplayDrawInstance : StdDisplay());
	}
	
	// Set breakpoint count and redraw user interface. It seems that empty an data set keeps the UI from redrawing.
	if (!bpCount)
	{
		this->mBreakpointsHitList.Clear();
	}
	else
	{
		this->mBreakpointsHitList.SetVirtualCount(bpCount);
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
		this->CryDebuggerEventOccuredThreadSafe(DBG_EVENT_BREAKPOINTS_CHANGED, NULL);
	}
}