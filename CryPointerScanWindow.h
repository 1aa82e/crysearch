#ifndef _CrySearch_CryPointerScanWindow_h_
#define _CrySearch_CryPointerScanWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Dialog that implements pointer scanning functionality.
class CryPointerScanWindow : public CryDialogTemplate
{
private:
	typedef CryPointerScanWindow CLASSNAME;
	
	MenuBar mMenuBar;
	CrySearchArrayCtrl mPointerScanResults;
	
	void WindowMenuBar(Bar& pBar);
	void FileMenuBar(Bar& pBar);
	void CloseWindow();
	void PointerScanRightClick(Bar& pBar);
	void NewPointerScanClicked();
public:
	CryPointerScanWindow(const Image& icon);
	~CryPointerScanWindow();
};

#endif