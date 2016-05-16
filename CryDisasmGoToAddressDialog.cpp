#include "CryDisasmGoToAddressDialog.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"

CryDisasmGoToAddressDialog::CryDisasmGoToAddressDialog(LONG_PTR* addr) : CryDialogTemplate(CrySearchIml::CrySearch())
{
	this->addrPtr = addr;
	
	this->Title("Go to Address").SetRect(0, 0, 180, 75);
		
	this->mOk <<= THISBACK(OkButtonClicked);
	this->mCancel <<= THISBACK(CancelButtonClicked);
		
	*this
		<< this->mAddressDesc.SetLabel("Address:").LeftPos(5, 75).TopPos(5, 25)
		<< this->mAddressInput.HSizePos(80, 5).TopPos(5, 25)
		<< this->mOk.Ok().SetLabel("OK").BottomPos(5, 25).RightPos(5, 60)
		<< this->mCancel.SetLabel("Cancel").BottomPos(5, 25).RightPos(70, 60)
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
	
	// If the address input contains a plus, the input is a relative address.
	const String& addrField = this->mAddressInput.GetText().ToString();
	const int plusIndex = addrField.Find("+");
	if (plusIndex != -1)
	{
		// Parse the relative address into the new address table entry.
		const Win32ModuleInformation* mod = mModuleManager->FindModule(addrField.Left(plusIndex));
		if (!mod)
		{
			// If the module was not found in the loaded modules list, the relative address cannot be calculated.
			Prompt("Input Error", CtrlImg::error(), "The typed module was not found!", "OK");
			return;
		}
			
		// Still here, so calculate the address.
		*this->addrPtr = mod->BaseAddress + ScanInt(addrField.Mid(plusIndex + 1), NULL, 16);
	}
	else
	{
		// Regularly parse the address. It is not a relative one.
#ifdef _WIN64
		*this->addrPtr = ScanInt64(addrField, NULL, 16);
#else
		*this->addrPtr = ScanInt(addrField, NULL, 16);
#endif
	}

	this->AcceptBreak(10);
}

void CryDisasmGoToAddressDialog::CancelButtonClicked()
{
	*this->addrPtr = -1;
	this->Close();
}