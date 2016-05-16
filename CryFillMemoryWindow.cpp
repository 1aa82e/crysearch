#include "CryFillMemoryWindow.h"
#include "ImlProvider.h"

// The default constructor of the CryFillMemoryWindow class.
CryFillMemoryWindow::CryFillMemoryWindow(FillMemoryDataStruct* dataStruct) : CryDialogTemplate(CrySearchIml::AllocateMemoryButton())
{
	this->dataStruct = dataStruct;
	
	this->Title("Fill Memory").SetRect(0, 0, 250, 145);
	this->Rejector(mCancel, IDCANCEL);
	
	this->mOk <<= THISBACK(OkButton);
	this->mCancel <<= THISBACK(CancelButton);
	this->mRandomizeValues.WhenAction = THISBACK(RandomizeValuesCheckedChanged);
	
	*this
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(70, 60).BottomPos(5, 25)
		<< this->mAddressDescriptor.SetLabel("Address:").HSizePos(5, 100).TopPos(5, 25)
		<< this->mAddress.HSizePos(110, 5).TopPos(5, 25)
		<< this->mMemorySizeDescriptor.SetLabel("Memory Size:").HSizePos(5, 100).TopPos(35, 25)
		<< this->mMemorySize.HSizePos(110, 5).TopPos(35, 25)
		<< this->mValueDescriptor.SetLabel("Value:").HSizePos(5, 100).TopPos(65, 25)
		<< this->mValueInput.HSizePos(110, 5).TopPos(65, 25)
		<< this->mRandomizeValues.SetLabel("Randomize memory").HSizePos(5, 5).TopPos(90, 25)
	;
	
	// Set default values for the fields in the dialog.
	this->mMemorySize.SetText("4096");
	this->mValueInput.SetText("0");
}

// The default destructor of the CryFillMemoryWindow class.
CryFillMemoryWindow::~CryFillMemoryWindow()
{
	
}

// Executed when the status of the checkbox for value randomization is changed.
void CryFillMemoryWindow::RandomizeValuesCheckedChanged()
{
	if (this->mRandomizeValues)
	{
		this->mValueDescriptor.Disable();
		this->mValueInput.Disable();
	}
	else
	{
		this->mValueDescriptor.Enable();
		this->mValueInput.Enable();
	}
}

// Executed when the OK button is clicked.
void CryFillMemoryWindow::OkButton()
{
#ifdef _WIN64
	this->dataStruct->Address = ScanInt64(this->mAddress.GetText().ToString(), NULL, 16);
#else
	this->dataStruct->Address = ScanInt(this->mAddress.GetText().ToString(), NULL, 16);
#endif

	// Check the validity of the address input field.
	if (this->dataStruct->Address <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "Please insert a valid hexadecimal memory address.", "OK");
		return;
	}
	
	this->dataStruct->MemorySize = ScanInt(this->mMemorySize.GetText().ToString(), NULL, 10);
	
	// Check the validity of the memory size input field.
	if (this->dataStruct->MemorySize <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "Please insert a valid decimal numeric value as memory size.", "OK");
		return;
	}
	
	// Check whether the user would like randomized values.
	if (this->mRandomizeValues)
	{
		this->dataStruct->Randomize = true;
	}
	else
	{
		// The user does not want randomized values. Check the validity of the value input field.
		const String& valueInput = this->mValueInput.GetText().ToString();
		if (valueInput.IsEmpty())
		{
			Prompt("Input Error", CtrlImg::error(), "Please insert a valid decimal numeric value.", "OK");
			return;
		}
		
		this->dataStruct->Value = ScanInt(valueInput, NULL, 10);
		this->dataStruct->Randomize = false;
	}

	this->AcceptBreak(10);
}

// Executed when the cancel button is clicked.
void CryFillMemoryWindow::CancelButton()
{
	this->Close();
}