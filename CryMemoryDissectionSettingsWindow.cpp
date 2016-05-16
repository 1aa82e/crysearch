#include "CryMemoryDissectionSettingsWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

CryMemoryDissectionSettingsWindow::CryMemoryDissectionSettingsWindow()
{
	this->Title("Settings").Icon(CrySearchIml::SettingsButton()).SetRect(0, 0, 300, 200);
	
	*this
		<< this->mDissectionSettings.SetLabel("Memory Dissection").HSizePos(5, 5).VSizePos(5, 35)
		<< this->mUpdateIntervalDesc.SetLabel("Update Interval:").LeftPos(10, 100).TopPos(20, 25)
		<< this->mUpdateInterval.HSizePos(115, 10).TopPos(20, 25)
		<< this->mDefaultViewAsHex.SetLabel("View values as hexadecimal by default").HSizePos(10, 10).TopPos(50, 25)
		<< this->mEnableTypeGuessing.SetLabel("Enable type guessing when dissecting").HSizePos(10, 10).TopPos(80, 25)
		<< this->mOK.Ok().SetLabel("OK").RightPos(70, 60).BottomPos(5, 25)
		<< this->mClose.SetLabel("Cancel").RightPos(5, 60).BottomPos(5, 25)
	;
	
	this->mOK <<= THISBACK(OkButtonClicked);
	this->mClose <<= THISBACK(CloseWindow);

	this->mSettingsInstance = SettingsFile::GetInstance();
	this->LoadSettings();
}

CryMemoryDissectionSettingsWindow::~CryMemoryDissectionSettingsWindow()
{
	
}

void CryMemoryDissectionSettingsWindow::OkButtonClicked()
{
	// Check input values for possible errors.
	const int interval = StrInt(this->mUpdateInterval.GetText().ToString());
	if (((String)this->mUpdateInterval).IsEmpty() || interval <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "The updater interval value is invalid.", "OK");
		return;
	}
	else
	{
		this->mSettingsInstance->SetDissectionUpdateInterval(interval);
	}
	
	// Set options in settings file.
	this->mSettingsInstance->SetDissectionHexadecimalView(this->mDefaultViewAsHex);
	this->mSettingsInstance->SetEnableDissectionTypeGuessing(this->mEnableTypeGuessing);
	
	this->mSettingsInstance->Save();
	this->AcceptBreak(10);
}

void CryMemoryDissectionSettingsWindow::CloseWindow()
{
	this->Close();
}

// ---------------------------------------------------------------------------------------------

void CryMemoryDissectionSettingsWindow::LoadSettings()
{
	this->mUpdateInterval.SetText(FormatIntSpecial(this->mSettingsInstance->GetDissectionUpdateInterval()));
	this->mDefaultViewAsHex = this->mSettingsInstance->GetDissectionHexadecimalView();
	this->mEnableTypeGuessing = this->mSettingsInstance->GetEnableDissectionTypeGuessing();
}