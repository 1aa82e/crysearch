#ifndef _CrySearch_CryDebuggerWindow_h_
#define _CrySearch_CryDebuggerWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CryDebugger.h"
#include "CryDebuggerHitView.h"

// Represents the debugger window in the user interface. All debugger interaction is done here.
class CryDebuggerWindow sealed : public ParentCtrl
{
private:
	Splitter mGlobalSplitter;
	Splitter mLeftSplitter;
	Splitter mRightSplitter;
	CrySearchArrayCtrl mBreakpointsHitList;
	CryDebuggerHitView mDebuggerHitView;
	CrySearchArrayCtrl mStackView;
	CrySearchArrayCtrl mCallStackView;

	void BreakpointListRightClick(Bar& pBar);
	void RemoveBreakpointButtonClicked();
	void BreakpointSelectionChanged();
	
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
