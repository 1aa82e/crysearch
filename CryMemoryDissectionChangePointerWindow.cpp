#include "CryMemoryDissectionChangePointerWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

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
	
#ifdef _WIN64
	const SIZE_T newptr = (SIZE_T)ScanInt64(addrField, NULL, 16);
#else
	const SIZE_T newptr = (SIZE_T)ScanInt(addrField, NULL, 16);
#endif
	
	// If a bogus value was entered, the following value should be returned.
	if (newptr == 0x80000000)
	{
		Prompt("Input Error", CtrlImg::error(), "The specified start address is incorrect. Please enter a hexadecimal value.", "OK");
		return;
	}
	
	*this->mPointer = newptr;
	this->AcceptBreak(10);
}