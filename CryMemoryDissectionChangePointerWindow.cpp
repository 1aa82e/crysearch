#include "CryMemoryDissectionChangePointerWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

CryMemoryDissectionChangePointerWindow::CryMemoryDissectionChangePointerWindow(SIZE_T* const pPointer) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
{
	this->mPointer = pPointer;
	this->Title("Change Pointer").SetRect(0, 0, 200, 100);
	
	*this
		<< this->mPointerFieldLabel.SetLabel("Address:").LeftPos(5, 60).TopPos(5, 25)
		<< this->mPointerField.HSizePos(65, 5).TopPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(5, 60).BottomPos(5, 25)
		<< this->mOK.Ok().SetLabel("OK").RightPos(70, 60).BottomPos(5, 25)
	;
	
	this->mOK <<= THISBACK(OkButtonClicked);
	this->Rejector(this->mCancel, IDCANCEL);
	
	// Load current pointer into text field.
#ifdef _WIN64
	this->mPointerField.SetText(FormatInt64HexUpper((LONG_PTR)*pPointer));
#else
	this->mPointerField.SetText(FormatHexadecimalIntSpecial((LONG_PTR)*pPointer));
#endif
}

CryMemoryDissectionChangePointerWindow::~CryMemoryDissectionChangePointerWindow()
{
	
}

void CryMemoryDissectionChangePointerWindow::OkButtonClicked()
{
	String addrField = this->mPointerField.GetText().ToString();
	
	// Check validity of start address.
	if (addrField.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a valid start address", "OK");
		return;
	}
	
	SIZE_T newptr;
	
	// If the address input contains a plus, the input is a relative address.
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
		newptr = mod->BaseAddress + ScanInt(addrField.Mid(plusIndex + 1), NULL, 16);
	}
	else
	{
		// Regularly parse the address. It is not a relative one.
#ifdef _WIN64
		newptr = ScanInt64(addrField, NULL, 16);
#else
		newptr = ScanInt(addrField, NULL, 16);
#endif
	}
	
	// If a bogus value was entered, the following value should be returned.
	if (newptr == 0x80000000)
	{
		Prompt("Input Error", CtrlImg::error(), "The specified start address is incorrect. Please enter a hexadecimal value.", "OK");
		return;
	}
	
	*this->mPointer = newptr;
	this->AcceptBreak(10);
}