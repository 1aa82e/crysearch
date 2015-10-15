#ifndef _CrySearch_CryFillMemoryDialog_h_
#define _CrySearch_CryFillMemoryDialog_h_

#include "CryDialogTemplate.h"

// Represents a data package that is needed to pass data from one window to another.
struct FillMemoryDataStruct
{
	SIZE_T Address;
	int MemorySize;
	int Value;
	bool Randomize;
};

// Represents the dialog that allows a user to specify a block of memory to be filled with (random) values.
class CryFillMemoryWindow : public CryDialogTemplate
{
private:
	FillMemoryDataStruct* dataStruct;

	Button mOk;
	Button mCancel;
	Label mAddressDescriptor;
	EditField mAddress;
	Label mMemorySizeDescriptor;
	EditField mMemorySize;
	Label mValueDescriptor;
	EditField mValueInput;
	Option mRandomizeValues;
	
	void OkButton();
	void CancelButton();
	void RandomizeValuesCheckedChanged();
	
	typedef CryFillMemoryWindow CLASSNAME;
public:
	CryFillMemoryWindow(FillMemoryDataStruct* dataStruct);
	~CryFillMemoryWindow();
};

#endif