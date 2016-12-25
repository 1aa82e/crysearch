#include "CryAllocateMemoryWindow.h"
#include "ImlProvider.h"

CryAllocateMemoryWindow::CryAllocateMemoryWindow(AllocateMemoryDataStruct* dataStruct) : CryDialogTemplate(CrySearchIml::AllocateMemoryButton())
{
	this->dataStruct = dataStruct;
	
	this->Title("Allocate Memory").SetRect(0, 0, 250, 100);
	this->Rejector(mCancel, IDCANCEL);
	
	this->mOk <<= THISBACK(OkButton);
	this->mCancel <<= THISBACK(CancelButton);
	
	*this
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 70).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(80, 70).BottomPos(5, 25)
		<< this->mMemorySizeDescriptor.SetLabel("Memory Size:").HSizePos(5, 100).TopPos(5, 25)
		<< this->mMemorySize.HSizePos(110, 5).TopPos(5, 25)
		<< this->mProtectionFieldDescriptor.SetLabel("Protection:").HSizePos(5, 100).TopPos(35, 25)
		<< this->mProtectionSelector.Add("Read-only").Add("Read-Write").HSizePos(110, 5).TopPos(35, 25)
	;
	
	this->mMemorySize.SetText("4096");
	this->mProtectionSelector.SetIndex(1);
}

CryAllocateMemoryWindow::~CryAllocateMemoryWindow()
{
	
}

void CryAllocateMemoryWindow::OkButton()
{
	this->dataStruct->MemorySize = ScanInt(this->mMemorySize.GetText().ToString(), NULL, 10);
	
	// Check the validity of the memory size input field.
	if (this->dataStruct->MemorySize <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "Please insert a valid decimal numeric value as memory size.", "OK");
		return;
	}
	
	this->dataStruct->BlockProtection = this->mProtectionSelector.GetIndex();
	
	this->AcceptBreak(10);
}

void CryAllocateMemoryWindow::CancelButton()
{
	this->Close();
}