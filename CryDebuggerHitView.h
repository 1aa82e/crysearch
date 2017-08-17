#ifndef _CrySearch_CryDebuggerHitView_h_
#define _CrySearch_CryDebuggerHitView_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"
#include "CryClickLabel.h"

// Custom control to display the instruction that triggered a breakpoint and the values of its registers at that time.
class CryDebuggerHitView : public ParentCtrl
{
private:
	SIZE_T disasmAddress;
	CryClickLabel mAccessedAddress;
	CrySearchArrayCtrl mRegisterView;
	
	void HitInstructionClicked();
	void CopyRegisterViewValue();
	void RegisterValueRightClick(Bar& pBar);
	
	typedef CryDebuggerHitView CLASSNAME;
public:
	CryDebuggerHitView();
	~CryDebuggerHitView();
	
	void SetRegisterCount(const int count);
	void SetTooltip(const char* tt);
	void SetInstructionString(const SIZE_T is);
	void ClearInstructionString();
};

#endif