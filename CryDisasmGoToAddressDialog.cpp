#include "CryDisasmGoToAddressDialog.h"
#include "ImlProvider.h"

CryDisasmGoToAddressDialog::CryDisasmGoToAddressDialog(LONG_PTR* addr) : CryDialogTemplate(CrySearchIml::CrySearch())
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

CryDisasmGoToAddressDialog::~CryDisasmGoToAddressDialog()
{
	
}

void CryDisasmGoToAddressDialog::OkButtonClicked()
{
	// Check if a valid address was entered.
	if (this->mAddressInput.GetText().IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter an address.", "OK");
		return;
	}
	
	// Save it in the return pointer and close the window.
#ifdef _WIN64
	*this->addrPtr = ScanInt64(this->mAddressInput.GetText().ToString(), NULL, 16);
#else
	*this->addrPtr = ScanInt(this->mAddressInput.GetText().ToString(), NULL, 16);
#endif

	this->AcceptBreak(10);
}

void CryDisasmGoToAddressDialog::CancelButtonClicked()
{
	*this->addrPtr = -1;
	this->Close();
}