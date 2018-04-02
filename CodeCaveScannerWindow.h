#ifndef _CrySearch_CodeCaveScannerWindow_h_
#define _CrySearch_CodeCaveScannerWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"
#include "MemoryScannerContext.h"
#include "CodeCaveScanner.h"

// Dialog that implements code cave scanning functionality.
class CodeCaveScannerWindow : public CryDialogTemplate
{
private:
	Button mClose;
	Button mScan;
	Label mScanPageLabel;
	DropList mScanPage;
	EditField mCodeCaveSize;
	Label mCaveSizeLabel;
	EditIntSpin mCaveSize;
	CrySearchArrayCtrl mScanResults;
	Vector<MemoryRegion> memoryRegions;
	CodeCaveScanner ccs;

	void ScanButtonClicked();
	void CloseButtonClicked();
	
	void ScannerStarted();
	void ScannerFinished();
	void ScannerFinishedThreadSafe();
	void ScannerResultFound(const SIZE_T addr, const int sz);
	void ScannerResultFoundThreadSafe(const SIZE_T addr, const int sz);
	
	void RightClicked(Bar& pBar);
	void CopyCursorAddressToClipboard();

	typedef CodeCaveScannerWindow CLASSNAME;
public:
	CodeCaveScannerWindow(const Image& icon);
	~CodeCaveScannerWindow();
};

#endif