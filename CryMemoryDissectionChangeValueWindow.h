#ifndef _CrySearch_CryMemoryDissectionChangeValueWindow_h_
#define _CrySearch_CryMemoryDissectionChangeValueWindow_h_

#include "CryDialogTemplate.h"
#include "MemoryDissector.h"

// Window for editing row values in the memory dissection window.
class CryMemoryDissectionChangeValueWindow : public CryDialogTemplate
{
private:
	SIZE_T address;
	CCryDataType rowType;
	int* size;
	
	Button mCancel;
	Button mOk;
	Label mFieldDescription;
	EditField mFieldValue;
	Option mUnicodeString;
	Option mValueIsHex;
	
	void CancelDialog();
	void DialogOkay();
	void ValueModeHexOptionChanged();
	
	typedef CryMemoryDissectionChangeValueWindow CLASSNAME;
public:
	CryMemoryDissectionChangeValueWindow(SIZE_T address, CCryDataType rowType, int* size);
	~CryMemoryDissectionChangeValueWindow();
};

#endif