#ifndef _CrySearch_CryHeapWalkDialog_h_
#define _CrySearch_CryHeapWalkDialog_h_

#include "CryDialogTemplate.h"

// Heap dialog that displays the heaps in the opened process.
class CryHeapWalkDialog sealed : public CryDialogTemplate
{
private:
	Button mClose;
	ArrayCtrl mHeapList;
	Label mHeapCount;
	
	void CloseDialog();
	
	typedef CryHeapWalkDialog CLASSNAME;
public:
	CryHeapWalkDialog(const Image& icon);
	~CryHeapWalkDialog();	
};

#endif
