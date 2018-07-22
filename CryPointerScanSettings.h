#ifndef _CrySearch_CryPointerScanSettings_h_
#define _CrySearch_CryPointerScanSettings_h_

#include "CryDialogTemplate.h"

// Represents the settings window for a new pointer scan.
class CryPointerScanSettings : public CryDialogTemplate
{
private:
	typedef CryPointerScanSettings CLASSNAME;
	
	Button mClose;
	Button mStartScan;
	
	void CloseWindow();
	void StartPointerScan();
public:
	CryPointerScanSettings(const Image& icon);
	~CryPointerScanSettings();
};

#endif