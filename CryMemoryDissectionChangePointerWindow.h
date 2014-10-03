#ifndef _CrySearch_CryMemoryDissectionChangePointerWindow_h_
#define _CrySearch_CryMemoryDissectionChangePointerWindow_h_

#include "CryDialogTemplate.h"

// Represents the pointer editing dialog that is called from the memory dissection window.
class CryMemoryDissectionChangePointerWindow : public CryDialogTemplate
{
private:
	SIZE_T* mPointer;
	
	Label mPointerFieldLabel;
	EditField mPointerField;
	Button mOK;
	Button mCancel;
	
	void OkButtonClicked();
	
	typedef CryMemoryDissectionChangePointerWindow CLASSNAME;
public:
	CryMemoryDissectionChangePointerWindow(SIZE_T* const pPointer);
	~CryMemoryDissectionChangePointerWindow();
};

#endif