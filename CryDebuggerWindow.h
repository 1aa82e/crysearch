#ifndef _CrySearch_CryDebuggerWindow_h_
#define _CrySearch_CryDebuggerWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CryDebugger.h"
#include "CryDebuggerHitView.h"

// Represents the debugger window in the user interface. All debugger interaction is done here.
class CryDebuggerWindow : public ParentCtrl
{
private:
	ToolBar mToolStrip;
	Splitter mGlobalSplitter;
	Splitter mLeftSplitter;
	Splitter mRightSplitter;
	CrySearchArrayCtrl mBreakpointsHitList;
	CryDebuggerHitView mDebuggerHitView;
	CrySearchArrayCtrl mStackView;
	CrySearchArrayCtrl mCallStackView;
	
	// For the thread safety of the debugger's operations, we need two semaphores.
	Semaphore mDebuggerEventLock;
	
	void ToolStrip(Bar& pBar);
	void BreakpointListRightClick(Bar& pBar);
	void CallStackListRightClick(Bar& pBar);
	
	void DynamicCreateStackView();
	void FollowStackTraceInDisassembler();
	void DisableBreakpointButtonClicked();
	void RemoveBreakpointButtonClicked();
	void BreakpointSelectionChanged();
	void DebuggerClearBreakpoints();
	void HandleBreakpointChanged(const int bpIndex);
	void DebuggerEventOccured(DebugEvent event, void* param);
	void DebuggerEventOccuredThreadsafe(DebugEvent event, void* param);
	void HandleUnhandledException(UnhandledExceptionData* param);
	
	typedef CryDebuggerWindow CLASSNAME;
public:
	CryDebuggerWindow();
	~CryDebuggerWindow();
	
	void Initialize();
	void Cleanup();
	void UpdateToolbar();
	
	Callback DebugErrorOccured;
};

#endif
