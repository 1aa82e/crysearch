#ifndef _CrySearch_CryMemoryDissectionNewWindow_h_
#define _CrySearch_CryMemoryDissectionNewWindow_h_

#include "CryDialogTemplate.h"
#include "AddressTable.h"

class CryMemoryDissectionNewWindow : public CryDialogTemplate
{
private:
	String* pStr;
	SIZE_T* pAddr;
	DWORD* pSize;
	
	Label mFriendlyNameDesc;
	EditField mFriendlyName;
	Label mPointerDesc;
	EditField mPointer;
	Label mSizeDesc;
	EditField mSizeField;
	Button mOK;
	Button mCancel;
	
	void OkButtonClicked();
	
	typedef CryMemoryDissectionNewWindow CLASSNAME;
public:
	CryMemoryDissectionNewWindow(String* pName, SIZE_T* pAddr, DWORD* pSize);
	~CryMemoryDissectionNewWindow();
};

#endif