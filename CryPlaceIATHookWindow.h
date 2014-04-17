#ifndef _CrySearch_CryPlaceIATHookWindow_h_
#define _CrySearch_CryPlaceIATHookWindow_h_

#include "CryDialogTemplate.h"

class CryPlaceIATHookWindow sealed : public CryDialogTemplate
{
private:
	char* mFunction;
	bool mOrdinal;
	
	Label mAddressDescription;
	EditField mAddressInput;
	Button mOk;
	Button mCancel;
	
	void DialogOkay();
	void DialogCancel();
	
	typedef CryPlaceIATHookWindow CLASSNAME;
public:
	CryPlaceIATHookWindow(const char* funcIdentifier, bool IsOrdinal);
	~CryPlaceIATHookWindow();	
};

#endif
