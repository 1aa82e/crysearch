#include "CryPointerScanSettings.h"
#include "ImlProvider.h"

// CryPointerScanSettings default constructor.
CryPointerScanSettings::CryPointerScanSettings(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Pointer Scan Settings").SetRect(0, 0, 320, 200);
	
	*this
		<< this->mStartScan.SetLabel("Start").LeftPos(5, 60).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").LeftPos(70, 60).BottomPos(5, 25)
	;
	
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
	
}

// Closes the settings window.
void CryPointerScanSettings::CloseWindow()
{
	this->Close();
}