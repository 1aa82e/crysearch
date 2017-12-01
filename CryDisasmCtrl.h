#ifndef _CrySearch_CryDisasmCtrl_h_
#define _CrySearch_CryDisasmCtrl_h_

#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"
#include "AsyncDisassembler.h"

// Disassembly control, which is used in a tab window. The opened process' code is disassembled
// and shown inside this control.
class CryDisasmCtrl : public ParentCtrl
{
private:
	bool mHasPreceding;
	bool mHasSucceeding;

	AsyncDisassembler mAsyncHelper;

	ToolBar mToolStrip;
	CrySearchArrayCtrl disasmDisplay;
	
	// Toolbar ctrls
	Label mExecutablePagesDescriptor;
	Label mPageSizeInDisasm;
	
	void ExecutablePagesDropped();
	void ExecutablePageSelected();
	
	void ToolStrip(Bar& pBar);
	void SetBreakpointMenu(Bar& pBar);
	void DisassemblyRightClick(Bar& pBar);
	void DisasmGenerateSubmenu(Bar& pBar);
	
	void MoveToPreviousPage();
	void MoveToNextPage();
	void RemoveBreakpointButtonClicked();
	void SetSoftwareBreakpoint();
	void SetHardwareBreakpoint();
	void GoToAddressButtonClicked();
	void CopyCursorLineToClipboard();
	void GenerateSignatureButtonClicked();
	void GenerateByteArrayButtonClicked();
	void NopSelectedCode();
	void GoToEntryPointClicked();
	void PeekDisasmCompletion();
	
	void AsyncDisasmStarted();
	
	virtual bool Key(dword key, int count);
	
	typedef CryDisasmCtrl CLASSNAME;
public:
	CryDisasmCtrl();
	~CryDisasmCtrl();
	
	void Initialize();
	void ClearList();
	
	void MoveToAddress(const SIZE_T address);
	void UpdateToolbar();
};

// The debugger needs this function to retrieve the correct breakpoint after a single step has been made. (INT3)
const int GetDisasmLineIndexFromAddress(const SIZE_T address);

#endif
