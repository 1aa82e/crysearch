#ifndef _CrySearch_CryMemoryDissectionSettingsWindow_h_
#define _CrySearch_CryMemoryDissectionSettingsWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "SettingsFile.h"

// Represents the settings window specific to the memory dissection options.
class CryMemoryDissectionSettingsWindow : public TopWindow
{
private:
	SettingsFile* mSettingsInstance;
	
	Button mOK;
	Button mClose;
	LabelBox mDissectionSettings;
	Label mUpdateIntervalDesc;
	EditField mUpdateInterval;
	Option mDefaultViewAsHex;
	Option mEnableTypeGuessing;
	
	void OkButtonClicked();
	void CloseWindow();
	
	void LoadSettings();
	
	typedef CryMemoryDissectionSettingsWindow CLASSNAME;
public:
	CryMemoryDissectionSettingsWindow();
	~CryMemoryDissectionSettingsWindow();
};

#endif