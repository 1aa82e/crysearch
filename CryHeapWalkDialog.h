#ifndef _CrySearch_CryHeapWalkDialog_h_
#define _CrySearch_CryHeapWalkDialog_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Heap dialog that displays the heaps in the opened process.
class CryHeapWalkDialog : public CryDialogTemplate
{
private:
	Button mClose;
	CrySearchArrayCtrl mHeapList;
	Label mHeapCount;
	
	void CloseDialog();
	
	typedef CryHeapWalkDialog CLASSNAME;
public:
	CryHeapWalkDialog(const Image& icon);
	~CryHeapWalkDialog();	
};

#endif
