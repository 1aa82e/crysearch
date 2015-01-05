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
	Option mValueIsHex;
	EditField mValueToSearchFor;
	DropList mBlockSizeSelector;
	Label mBlockSizeSelectorLabel;
	Label mScanTypeSelectorLabel;
	DropList mScanTypeSelector;
	Option useFastScan;
	Option stringUnicode;
	
	void ValueInputHexToggleChanged();
	void ScanTypeSelected();
	void BlockSizeSelected();
	void OkButtonClicked();
	
	friend class CrySearchForm;
public:
	CryNewScanForm(bool FirstScan, const Image& icon);
	~CryNewScanForm();

	typedef CryNewScanForm CLASSNAME;
	
	Callback2<const ScanParameterBase*, MemoryScanValueType> ScanTriggered;
};

#endif
