#ifndef _CrySearch_CryAllocateMemoryWindow_h_
#define _CrySearch_CryAllocateMemoryWindow_h_

#include "CryDialogTemplate.h"

// Represents a data package that is needed to pass data from one window to another.
struct AllocateMemoryDataStruct
{
	int MemorySize;
	int BlockProtection;
};

class CryAllocateMemoryWindow : public CryDialogTemplate
{
private:
	AllocateMemoryDataStruct* dataStruct;

	Button mOk;
	Button mCancel;
	Label mMemorySizeDescriptor;
	EditField mMemorySize;
	Label mProtectionFieldDescriptor;
	DropList mProtectionSelector;
	
	void OkButton();
	void CancelButton();
	
	typedef CryAllocateMemoryWindow CLASSNAME;
public:
	CryAllocateMemoryWindow(AllocateMemoryDataStruct* dataStruct);
	~CryAllocateMemoryWindow();	
};

#endif
