#include "CryCreateExternalThreadWindow.h"
#include "BackendGlobalDef.h"

// CryCreateExternalThreadWindow default constructor.
CryCreateExternalThreadWindow::CryCreateExternalThreadWindow(CreateNewThreadStruct* outStructDataPtr, const Image& icon) : CryDialogTemplate(icon)
{
	this->outStructDataPtr = outStructDataPtr;
	
	this->Title("Create thread").SetRect(0, 0, 300, 150);
	
	this->mOk <<= THISBACK(OkButton);
	this->mCancel <<= THISBACK(CancelButton);
	
	*this
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 70).BottomPosZ(5, 20)
		<< this->mCancel.SetLabel("Cancel").RightPos(80, 70).BottomPosZ(5, 20)
		<< this->mStartAddressDescriptor.SetLabel("Start address (Hex):").LeftPosZ(5, 140).TopPosZ(5, 20)
		<< this->mStartAddressEditField.HSizePosZ(150, 5).TopPosZ(5, 20)
		<< this->mParameterDescriptor.SetLabel("Parameter pointer (Hex):").LeftPosZ(5, 140).TopPosZ(30, 20)
		<< this->mParameterEditField.HSizePosZ(150, 5).TopPosZ(30, 20)
		<< this->mStartSuspended.SetLabel("Start thread in suspended state").HSizePosZ(5, 5).TopPos(80, 25)
	;
}

// CryCreateExternalThreadWindow default destructor.
CryCreateExternalThreadWindow::~CryCreateExternalThreadWindow()
{
	
}

// Executed when the user accepts the dialog input.
void CryCreateExternalThreadWindow::OkButton()
{
	String addrField = this->mStartAddressEditField.GetText().ToString();
	
	// Check validity of start address.
	if (addrField.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a valid start address", "OK");
		return;
	}

	// If the start address field contains a '!', it's to be parsed as an API.
	// Check for bigger than 0 because the name of the DLL must be in front of the '!'.
	int exclamationPos;
	if ((exclamationPos = addrField.Find("!")) > 0)
	{
		String dllName(addrField, exclamationPos);
		addrField.Remove(0, exclamationPos < addrField.GetLength() ? exclamationPos + 1 : 0);
		
		// Check whether the module has been found or not.
		const Win32ModuleInformation* dll = mModuleManager->FindModule(dllName);
		if (!dll)
		{
			Prompt("Fatal Error", CtrlImg::error(), "The DLL was not found in the target process!", "OK");
			return;
		}
		
		// Get the address of the function.
#ifdef _WIN64
		if (mMemoryScanner->IsX86Process())
		{
			this->outStructDataPtr->StartAddress = Wow64GetProcAddress(mMemoryScanner->GetHandle(), (DWORD)dll->BaseAddress, addrField);
		}
		else
		{
			this->outStructDataPtr->StartAddress = (SIZE_T)GetProcAddress((HMODULE)dll->BaseAddress, addrField);
		}
#else
		this->outStructDataPtr->StartAddress = (SIZE_T)GetProcAddress((HMODULE)dll->BaseAddress, addrField);
#endif
		
		// Check if the function has been found in the module.
		if (!this->outStructDataPtr->StartAddress)
		{
			Prompt("Fatal Error", CtrlImg::error(), "The function was not found in the target module!", "OK");
			return;
		}
	}
	else
	{
#ifdef _WIN64
		this->outStructDataPtr->StartAddress = (SIZE_T)ScanInt64(addrField, NULL, 16);
#else
		this->outStructDataPtr->StartAddress = (SIZE_T)ScanInt(addrField, NULL, 16);
#endif

		if (this->outStructDataPtr->StartAddress == 0x80000000)
		{
			Prompt("Input Error", CtrlImg::error(), "The specified start address is incorrect. Please enter a hexadecimal value.", "OK");
			return;
		}
	}

	// Check if the parameter is specified. If not, display a warning.
	if (this->mParameterEditField.GetText().IsEmpty())
	{
		if (!Prompt("Warning", CtrlImg::exclamation(), "The parameter field is left empty, which will pass a NULL pointer to the function."\
			" Do you want to continue?", "Yes", "No"))
		{
			return;
		}
		else
		{
			this->outStructDataPtr->ParameterPointer = NULL;
		}
	}
	else
	{
#ifdef _WIN64
		this->outStructDataPtr->ParameterPointer = (void*)ScanInt64(this->mParameterEditField.GetText().ToString(), NULL, 16);
#else
		this->outStructDataPtr->ParameterPointer = (void*)ScanInt(this->mParameterEditField.GetText().ToString(), NULL, 16);
#endif	
	}
	
	// Do we need the thread to start in suspended state?
	this->outStructDataPtr->StartSuspended = this->mStartSuspended ? TRUE : FALSE;
	
	this->AcceptBreak(10);
}

// Executed when the user closes the dialog without accepting the input.
void CryCreateExternalThreadWindow::CancelButton()
{
	this->Close();
}