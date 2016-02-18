#include "CryMemoryDissectionNewWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

CryMemoryDissectionNewWindow::CryMemoryDissectionNewWindow(String* pName, SIZE_T* pAddr, DWORD* pSize) : CryDialogTemplate(CrySearchIml::AddToAddressList())
{
	this->pStr = pName;
	this->pAddr = pAddr;
	this->pSize = pSize;
	this->Title("New Dissection").SetRect(0, 0, 250, 130);
	
	*this
		<< this->mFriendlyNameDesc.SetLabel("Name:").LeftPos(5, 60).TopPos(5, 25)
		<< this->mFriendlyName.HSizePos(70, 5).TopPos(5, 25)
		<< this->mPointerDesc.SetLabel("Pointer:").LeftPos(5, 60).TopPos(35, 25)
		<< this->mPointer.HSizePos(70, 5).TopPos(35, 25)
		<< this->mSizeDesc.SetLabel("Size:").LeftPos(5, 60).TopPos(65, 25)
		<< this->mSizeField.HSizePos(70, 5).TopPos(65, 25)
		<< this->mOK.Ok().SetLabel("OK").RightPos(70, 60).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(5, 60).BottomPos(5, 25)
	;
	
	this->mOK <<= THISBACK(OkButtonClicked);
	this->Rejector(this->mCancel, IDCANCEL);
	
	// Set current field values in fields. This option is for address table redirections.
	if (*pAddr && *pSize)
	{
		this->mFriendlyName.SetText(*pName);
#ifdef _WIN64
		this->mPointer.SetText(FormatInt64HexUpper((LONG_PTR)*pAddr));
#else
		this->mPointer.SetText(FormatHexadecimalIntSpecial((LONG_PTR)*pAddr));
#endif
		this->mSizeField.SetText(FormatIntSpecial(*pSize));
	}
}

CryMemoryDissectionNewWindow::~CryMemoryDissectionNewWindow()
{
	
}

void CryMemoryDissectionNewWindow::OkButtonClicked()
{
	String nameField = this->mFriendlyName.GetText().ToString();
	String addrField = this->mPointer.GetText().ToString();
	String sizeField = this->mSizeField.GetText().ToString();
	
	// Check validity of friendly name.
	if (nameField.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a friendly name.", "OK");
		return;
	}
	
	// Check validity of start address.
	if (addrField.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a valid start address", "OK");
		return;
	}
	
	// Check validity of size parameter.
	if (sizeField.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a valid size parameter.", "OK");
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
	
	const int sizeParam = StrInt(sizeField);
	
	// If a bogus address was entered, the creation should be cancelled.
	if (newptr == 0x80000000)
	{
		Prompt("Input Error", CtrlImg::error(), "The specified start address is incorrect. Please enter a hexadecimal value.", "OK");
		return;
	}
	
	//If the size parameter was a bogus value, the creation should be cancelled.
	if (sizeParam == 0x80000000)
	{
		Prompt("Input Error", CtrlImg::error(), "The specified size parameter is incorrect. Please enter a valid decimal value.", "OK");
		return;
	}
	
	// The size parameter may not be smaller than zero.
	if (sizeParam <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "The specified size parameter is incorrect. Please enter a value higher than zero.", "OK");
		return;
	}
	
	// Store values in new memory dissection entry.
	*this->pAddr = newptr;
	*this->pStr = nameField;
	*this->pSize = sizeParam;
		
	this->AcceptBreak(10);
}