#ifndef _CrySearch_CryPointerScanWindow_h_
#define _CrySearch_CryPointerScanWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"
#include "PointerScanner.h"

// Dialog that implements pointer scanning functionality.
class CryPointerScanWindow : public TopWindow
{
private:
	typedef CryPointerScanWindow CLASSNAME;
	
	MenuBar mMenuBar;
	CrySearchArrayCtrl mPointerScanResults;
	PointerScanner mPScanner;
	Label mMenuBarStatusLabel;
	
	void WindowMenuBar(Bar& pBar);
	void FileMenuBar(Bar& pBar);
	void EditMenuBar(Bar& pBar);
	void CloseWindow();
	void PointerScanRightClick(Bar& pBar);
	void NewPointerScanClicked();
	void PointerScanCheckForResults();
	void ClearResultsClicked();
	
	void StartNewPointerScan(const SIZE_T pAddr, const SIZE_T pMaxOff, const SIZE_T pMaxRec);
public:
	CryPointerScanWindow(const Image& icon);
	~CryPointerScanWindow();
};

#endif