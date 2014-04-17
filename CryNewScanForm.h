#ifndef _CrySearch_CryNewScanForm_h_
#define _CrySearch_CryNewScanForm_h_

#pragma warning(disable : 4005)

#include "GlobalDef.h"
#include "CryDialogTemplate.h"

class CryNewScanForm sealed : public CryDialogTemplate
{
private:
	bool mNextScan;

	Button mOk;
	Button mCancel;
	Label mValueInfoLabel;
	EditField mValueToSearchFor;
	DropList mBlockSizeSelector;
	Label mBlockSizeSelectorLabel;
	Label mScanTypeSelectorLabel;
	DropList mScanTypeSelector;
	Option useFastScan;
	Option stringUnicode;
	
	void ScanTypeSelected();
	void BlockSizeSelected();
	void OkButtonClicked();
	
	friend class CrySearchForm;
public:
	CryNewScanForm(bool FirstScan = true);
	~CryNewScanForm();

	typedef CryNewScanForm CLASSNAME;
	
	Callback2<const ScanParameterBase*, MemoryScanValueType> ScanTriggered;
};

#endif
