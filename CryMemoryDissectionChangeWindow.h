#ifndef _CryMemoryDissectionChangeWindow_h
#define _CryMemoryDissectionChangeWindow_h

#include "CryDialogTemplate.h"

// Represents the pointer editing dialog that is called from the memory dissection window.
class CryMemoryDissectionChangeWindow : public CryDialogTemplate
{
private:
	SIZE_T* mPointer;
	SIZE_T* mSize;
	
	Label mPointerFieldLabel;
	EditField mPointerField;
	Label mSizeFieldLabel;
	EditField mSizeField;
	Button mOK;
	Button mCancel;
	
	void OkButtonClicked();
	
	typedef CryMemoryDissectionChangeWindow CLASSNAME;
public:
	CryMemoryDissectionChangeWindow(SIZE_T* const pPointer, SIZE_T* const pSize);
	~CryMemoryDissectionChangeWindow();
};

#endif