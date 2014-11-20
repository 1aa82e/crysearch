#include "CryPlaceIATHookWindow.h"
#include "BackendGlobalDef.h"

CryPlaceIATHookWindow::CryPlaceIATHookWindow(const Win32ModuleInformation* pMod, const char* funcIdentifier, bool IsOrdinal, const Image& icon) : CryDialogTemplate(icon)
{
	this->mFunction = (char*)funcIdentifier;
	this->mOrdinal = IsOrdinal;
	this->mMod = pMod;
	
	this->Title("Set IAT Hook").SetRect(0, 0, 300, 75);
	
	this->mOk <<= THISBACK(DialogOkay);
	this->mCancel <<= THISBACK(DialogCancel);
	
	*this
		<< this->mAddressDescription.SetLabel("Detour Address:").HSizePos(5, 5).TopPos(5, 20)
		<< this->mAddressInput.HSizePos(130, 5).TopPos(5, 20)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 20)
		<< this->mCancel.SetLabel("Cancel").RightPos(70, 60).BottomPos(5, 20)
	;
}

CryPlaceIATHookWindow::~CryPlaceIATHookWindow()
{
	
}

void CryPlaceIATHookWindow::DialogOkay()
{
	// Check whether the input is not empty or retarded.
	String text = this->mAddressInput.GetText().ToString();
	if (!text.IsEmpty() || (text.GetLength() > 0 && text.GetLength() <= 16))
	{
#ifdef _WIN64
		mPeInstance->PlaceIATHook(this->mMod, this->mFunction, ScanInt64(text, NULL, 16), this->mOrdinal);
#else
		mPeInstance->PlaceIATHook(this->mMod, this->mFunction, ScanInt(text, NULL, 16), this->mOrdinal);
#endif
	}
	else
	{
		Prompt("Input error", CtrlImg::error(), "Please enter an address", "OK");
		return;
	}
	
	this->Close();
}

void CryPlaceIATHookWindow::DialogCancel()
{
	this->Close();
}