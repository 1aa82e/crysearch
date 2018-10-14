#ifndef _CrySearch_CryPointerScanSettings_h_
#define _CrySearch_CryPointerScanSettings_h_

#include "CryDialogTemplate.h"

// Represents the settings window for a new pointer scan.
class CryPointerScanSettings : public CryDialogTemplate
{
private:
	typedef CryPointerScanSettings CLASSNAME;
	
	SIZE_T* localAddr;
	SIZE_T* localMaxRecursion;
	SIZE_T* localMaxOffset;
	
	Label mAddrDesc;
	EditField mAddrField;
	Label mMaxOffsetDesc;
	EditField mMaxOffset;
	Label mMaxRecursionLevelLabel;
	EditField mMaxRecursionLevel;
	
	Button mClose;
	Button mStartScan;
	
	void CloseWindow();
	void StartPointerScan();
public:
	CryPointerScanSettings(const Image& icon, SIZE_T* pAddr, SIZE_T* pMaxOffset, SIZE_T* pMaxRecursion);
	~CryPointerScanSettings();
};

#endif