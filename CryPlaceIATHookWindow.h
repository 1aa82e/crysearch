#ifndef _CrySearch_CryPlaceIATHookWindow_h_
#define _CrySearch_CryPlaceIATHookWindow_h_

#include "CryDialogTemplate.h"
#include "ProcessUtil.h"

// Represents the dialog that handles setting a hook in the import table of a process.
class CryPlaceIATHookWindow : public CryDialogTemplate
{
private:
	SIZE_T* mAddress;

	Label mAddressDescription;
	EditField mAddressInput;
	Button mOk;
	Button mCancel;
	
	void DialogOkay();
	void DialogCancel();
	
	typedef CryPlaceIATHookWindow CLASSNAME;
public:
	CryPlaceIATHookWindow(SIZE_T* const pAddress, const Image& icon);
	~CryPlaceIATHookWindow();	
};

#endif
