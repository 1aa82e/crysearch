#ifndef _CrySearch_CryNewScanForm_h_
#define _CrySearch_CryNewScanForm_h_

#pragma warning(disable : 4005)

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "GlobalDef.h"

class CryNewScanForm sealed : public TopWindow
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
	
	virtual bool Key(dword key, int count);
	
	friend class CrySearchForm;
public:
	CryNewScanForm(bool FirstScan = true);
	~CryNewScanForm();

	typedef CryNewScanForm CLASSNAME;
	
	Callback2<const ScanParameterBase*, MemoryScanValueType> ScanTriggered;
};

#endif
