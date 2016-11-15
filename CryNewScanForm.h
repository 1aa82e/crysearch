#ifndef _CrySearch_CryNewScanForm_h_
#define _CrySearch_CryNewScanForm_h_

#include "CryDialogTemplate.h"
#include "MemoryScanner.h"

// Represents the dialog that handles a memory scan on a process.
class CryNewScanForm : public CryDialogTemplate
{
private:
	bool mNextScan;

	Button mOk;
	Button mCancel;
	Label mValueInfoLabel;
	Label mValueSecondInfoLabel;
	Option mValueIsHex;
	EditField mValueToSearchFor;
	EditField mSecondValueToSearchFor;
	DropList mBlockSizeSelector;
	Label mBlockSizeSelectorLabel;
	Label mScanTypeSelectorLabel;
	DropList mScanTypeSelector;
	Option useFastScan;
	Option stringUnicode;
	Option stringUntilNull;
	
	void ValueInputHexToggleChanged();
	void ScanTypeSelected();
	void BlockSizeSelected();
	void OkButtonClicked();
public:
	CryNewScanForm(bool FirstScan, const Image& icon);
	~CryNewScanForm();

	typedef CryNewScanForm CLASSNAME;
};

#endif
