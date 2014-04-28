#ifndef _CrySearch_CryCreateExternalThreadWindow_h_
#define _CrySearch_CryCreateExternalThreadWindow_h_

#include  "CryDialogTemplate.h"

// Represents a data package that can be used to travel data around the thread manager windows.
struct CreateNewThreadStruct
{
	SIZE_T StartAddress;
	void* ParameterPointer;
	bool StartSuspended;
};

class CryCreateExternalThreadWindow sealed : public CryDialogTemplate
{
private:
	CreateNewThreadStruct* outStructDataPtr;

	Button mOk;
	Button mCancel;
	Label mStartAddressDescriptor;
	EditField mStartAddressEditField;
	Label mParameterDescriptor;
	EditField mParameterEditField;
	Option mStartSuspended;
	
	void OkButton();
	void CancelButton();
	
	typedef CryCreateExternalThreadWindow CLASSNAME;
public:
	CryCreateExternalThreadWindow(CreateNewThreadStruct* outStructDataPtr);
	~CryCreateExternalThreadWindow();
};

#endif
