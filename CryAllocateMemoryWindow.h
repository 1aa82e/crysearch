#ifndef _CrySearch_CryAllocateMemoryWindow_h_
#define _CrySearch_CryAllocateMemoryWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents a data package that is needed to pass data from one window to another.
struct AllocateMemoryDataStruct
{
	unsigned int MemorySize;
	int BlockProtection;
};

class CryAllocateMemoryWindow sealed : public TopWindow
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
	
	virtual bool Key(dword key, int count);
	
	typedef CryAllocateMemoryWindow CLASSNAME;
public:
	CryAllocateMemoryWindow(AllocateMemoryDataStruct* dataStruct);
	~CryAllocateMemoryWindow();	
};

#endif
