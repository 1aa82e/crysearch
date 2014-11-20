#ifndef _CrySearch_CryPlaceIATHookWindow_h_
#define _CrySearch_CryPlaceIATHookWindow_h_

#include "CryDialogTemplate.h"
#include "ProcessUtil.h"

class CryPlaceIATHookWindow : public CryDialogTemplate
{
private:
	char* mFunction;
	bool mOrdinal;
	const Win32ModuleInformation* mMod;
	
	Label mAddressDescription;
	EditField mAddressInput;
	Button mOk;
	Button mCancel;
	
	void DialogOkay();
	void DialogCancel();
	
	typedef CryPlaceIATHookWindow CLASSNAME;
public:
	CryPlaceIATHookWindow(const Win32ModuleInformation* pMod, const char* funcIdentifier, bool IsOrdinal, const Image& icon);
	~CryPlaceIATHookWindow();	
};

#endif
