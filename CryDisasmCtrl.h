#ifndef _CrySearch_CryDisasmCtrl_h_
#define _CrySearch_CryDisasmCtrl_h_

#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"
#include "AsyncDisassembler.h"

// Disassembly control, can be placed on a tab page.
class CryDisasmCtrl : public ParentCtrl
{
private:
	AsyncDisassembler* mAsyncHelper;

	ToolBar mToolStrip;
	CrySearchArrayCtrl disasmDisplay;
	
	// Toolbar ctrls
	Label mExecutablePagesDescriptor;
	VirtualDropList mExecutablePages;
	
	void ExecutablePagesDropped();
	void ExecutablePageSelected();
	
	void ToolStrip(Bar& pBar);
	void SetBreakpointMenu(Bar& pBar);
	void DisassemblyRightClick(Bar& pBar);
	void DisasmGenerateSubmenu(Bar& pBar);
	
	void HeapWalkMenuClicked();
	void RemoveBreakpointButtonClicked();
	void SetSoftwareBreakpoint();
	void SetHardwareBreakpoint();
	void GoToAddressButtonClicked();
	void CopyCursorLineToClipboard();
	void GenerateSignatureButtonClicked();
	void GenerateByteArrayButtonClicked();
	
	void AsyncDisasmStarted();
	void AsyncDisasmCompleted(SIZE_T address);
	void AsyncDisasmCompletedThreadSafe(const SIZE_T address);
	
	virtual bool Key(dword key, int count);
	
	typedef CryDisasmCtrl CLASSNAME;
public:
	CryDisasmCtrl();
	~CryDisasmCtrl();
	
	void Initialize();
	void ClearList();
	
	void MoveToAddress(const SIZE_T address);
};

// The debugger needs this function to retrieve the correct breakpoint after a single step has been made. (INT3)
const int GetDisasmLineIndexFromAddress(const SIZE_T address);

#endif
