#ifndef _CrySearch_CryDisasmCtrl_h_
#define _CrySearch_CryDisasmCtrl_h_

#include "CrySearchArrayCtrl.h"
#include "VirtualDropList.h"
#include "AsyncDisassembler.h"

// Small dialog that is opened when the 'Go to address' context menu action is chosen from the disassembly view.
class CryDisasmGoToAddressDialog sealed : public TopWindow
{
private:
	Label mAddressDesc;
	EditField mAddressInput;
	Button mOk;
	Button mCancel;
	
	LONG_PTR* addrPtr;
	
	virtual bool Key(dword key, int count)
	{
		if (key == K_ESCAPE)
		{
			*addrPtr = -1;
			this->Close();
			return true;
		}
		
		return false;
	}
	
	void OkButtonClicked()
	{
		if (this->mAddressInput.GetText().IsEmpty())
		{
			Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
			return;
		}
		
#ifdef _WIN64
		*this->addrPtr = ScanInt64(this->mAddressInput.GetText().ToString(), NULL, 16);
#else
		*this->addrPtr = ScanInt(this->mAddressInput.GetText().ToString(), NULL, 16);
#endif

		this->Close();
	}
	
	void CancelButtonClicked()
	{
		*addrPtr = -1;
		this->Close();
	}
	
	typedef CryDisasmGoToAddressDialog CLASSNAME;
public:
	CryDisasmGoToAddressDialog(LONG_PTR* addr)
	{
		this->addrPtr = addr;
		
		this->Title("Go to Address").SetRect(0, 0, 180, 75);
		
		this->mOk <<= THISBACK(OkButtonClicked);
		this->mCancel <<= THISBACK(CancelButtonClicked);
		
		*this
			<< this->mAddressDesc.SetLabel("Address:").LeftPos(5, 75).TopPos(5, 20)
			<< this->mAddressInput.HSizePos(80, 5).TopPos(5, 20)
			<< this->mOk.Ok().SetLabel("OK").BottomPos(5, 20).RightPos(5, 60)
			<< this->mCancel.SetLabel("Cancel").BottomPos(5, 20).RightPos(70, 60)
		;
	}
	
	~CryDisasmGoToAddressDialog() {}
};

// Disassembly control, can be placed on a tab page.
class CryDisasmCtrl sealed : public ParentCtrl
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
	
	void HeapWalkMenuClicked();
	void RemoveBreakpointButtonClicked();
	void SetSoftwareBreakpoint();
	void SetHardwareBreakpoint();
	void GoToAddressButtonClicked();
	void CopyCursorLineToClipboard();
	
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
