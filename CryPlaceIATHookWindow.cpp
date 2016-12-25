#include "CryPlaceIATHookWindow.h"
#include "BackendGlobalDef.h"

// CryPlaceIATHookWindow default constructor.
CryPlaceIATHookWindow::CryPlaceIATHookWindow(SIZE_T* const pAddress, const Image& icon) : CryDialogTemplate(icon)
{
	this->mAddress = pAddress;
	this->Title("Set IAT Hook").SetRect(0, 0, 300, 75);
	
	this->mOk <<= THISBACK(DialogOkay);
	this->mCancel <<= THISBACK(DialogCancel);
	
	*this
		<< this->mAddressDescription.SetLabel("Detour Address:").HSizePos(5, 5).TopPos(5, 25)
		<< this->mAddressInput.HSizePos(130, 5).TopPos(5, 25)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 70).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(80, 70).BottomPos(5, 25)
	;
}

// CryPlaceIATHookWindow default destructor.
CryPlaceIATHookWindow::~CryPlaceIATHookWindow()
{
	
}

// Executed when the user accepts the dialog input.
void CryPlaceIATHookWindow::DialogOkay()
{
	// Check whether the input is not empty or retarded.
	String text = this->mAddressInput.GetText().ToString();
	if (!text.IsEmpty() || (text.GetLength() > 0 && text.GetLength() <= 16))
	{
#ifdef _WIN64
		*this->mAddress = ScanInt64(text, NULL, 16);
#else
		*this->mAddress = ScanInt(text, NULL, 16);
#endif
	}
	else
	{
		Prompt("Input error", CtrlImg::error(), "Please enter an address", "OK");
		return;
	}
	
	this->AcceptBreak(10);
}

// Executed when the user closes the dialog without accepting the input.
void CryPlaceIATHookWindow::DialogCancel()
{
	this->Close();
}