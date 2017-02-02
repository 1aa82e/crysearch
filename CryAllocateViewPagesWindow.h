#ifndef _CrySearch_CryAllocateViewPagesWindow_h_
#define _CrySearch_CryAllocateViewPagesWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// A utility window that allows users to view all memory pages currently allocated.
class CryAllocateViewPagesWindow : public CryDialogTemplate
{
private:
	Button mClose;
	Label mNumberOfCommittedPages;
	CrySearchArrayCtrl mPagesCtrl;
	
	void PagesListRightClick(Bar& pBar);
	
	void FreePageButton();
	void CloseButton();
	void Initialize();
	
	typedef CryAllocateViewPagesWindow CLASSNAME;
public:
	CryAllocateViewPagesWindow();
	~CryAllocateViewPagesWindow();
};

#endif
