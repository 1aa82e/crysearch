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
	
	void ToolStrip(Bar& pBar);
	void BreakpointListRightClick(Bar& pBar);
	void CallStackListRightClick(Bar& pBar);
	
	void FollowStackTraceInDisassembler();
	void DisableBreakpointButtonClicked();
	void RemoveBreakpointButtonClicked();
	void BreakpointSelectionChanged();
	void DebuggerClearBreakpoints();
	
	void CryDebuggerEventOccured(DebugEvent event, void* param);
	void CryDebuggerEventOccuredThreadSafe(DebugEvent event, void* param);
	
	typedef CryDebuggerWindow CLASSNAME;
public:
	CryDebuggerWindow();
	~CryDebuggerWindow();
	
	void Initialize();
	void Cleanup();
	
	Callback DebugErrorOccured;
};

#endif
