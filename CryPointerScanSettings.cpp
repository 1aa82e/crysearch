#include "CryPointerScanSettings.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"

// CryPointerScanSettings default constructor.
CryPointerScanSettings::CryPointerScanSettings(const Image& icon, SIZE_T* pAddr, SIZE_T* pMaxOffset, SIZE_T* pMaxRecursion) : CryDialogTemplate(icon)
{
	this->localAddr = pAddr;
	this->localMaxOffset = pMaxOffset;
	this->localMaxRecursion = pMaxRecursion;
	this->Title("Pointer Scan Settings").SetRect(0, 0, 320, 200);
	
	*this
		<< this->mAddrDesc.SetLabel("Address:").LeftPos(10, 135).TopPos(5, 25)
		<< this->mAddrField.HSizePos(150, 5).TopPos(5, 25)
		<< this->mMaxOffsetDesc.SetLabel("Maximum Offset:").LeftPos(10, 135).TopPos(35, 25)
		<< this->mMaxOffset.HSizePos(150, 5).TopPos(35, 25)
		<< this->mMaxRecursionLevelLabel.SetLabel("Maximum Recursion:").LeftPos(10, 135).TopPos(65, 25)
		<< this->mMaxRecursionLevel.HSizePos(150, 5).TopPos(65, 25)
		<< this->mStartScan.SetLabel("Start").LeftPos(5, 60).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").LeftPos(70, 60).BottomPos(5, 25)
	;
	
	// Set default parameter values.
	this->mMaxOffset.SetText("1024");
	this->mMaxRecursionLevel.SetText("3");
	
	this->mStartScan <<= THISBACK(StartPointerScan);
	this->mClose <<= THISBACK(CloseWindow);
}

// CryPointerScanSettings default destructor.
CryPointerScanSettings::~CryPointerScanSettings()
{
	
}

// Starts a new pointer scan with the chosen settings.
void CryPointerScanSettings::StartPointerScan()
{
	String addrField = this->mAddrField.GetText().ToString();
	String maxOffsetField = this->mMaxOffset.GetText().ToString();
	String maxRecursionField = this->mMaxRecursionLevel.GetText().ToString();
	
	// Check for empty input values.
	if (addrField.IsEmpty() || maxOffsetField.IsEmpty() || maxRecursionField.IsEmpty())
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter all parameters!", "OK");
		return;
	}
	
	SIZE_T newptr;
	SIZE_T maxoffset;
	SIZE_T maxrecursion;
	
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
	
	// Store the max offset and recursion.
	maxoffset = StrInt(maxOffsetField);
	maxrecursion = StrInt(maxRecursionField);
	
	// If a bogus value was entered, the scan should not be started.
	if (newptr == 0x80000000 || maxoffset == 0x80000000 || maxrecursion == 0x8000000)
	{
		Prompt("Input Error", CtrlImg::error(), "One of the parameters is incorrect! Please check the values.", "OK");
		return;
	}
	
	*this->localAddr = newptr;
	*this->localMaxOffset = maxoffset;
	*this->localMaxRecursion = maxrecursion;
	this->AcceptBreak(10);
}

// Closes the settings window.
void CryPointerScanSettings::CloseWindow()
{
	this->Close();
}