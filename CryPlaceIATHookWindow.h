#ifndef _CrySearch_CryPlaceIATHookWindow_h_
#define _CrySearch_CryPlaceIATHookWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class CryPlaceIATHookWindow sealed : public TopWindow
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
	
	virtual bool Key(dword key, int count);
	
	typedef CryPlaceIATHookWindow CLASSNAME;
public:
	CryPlaceIATHookWindow(const char* funcIdentifier, bool IsOrdinal);
	~CryPlaceIATHookWindow();	
};

#endif
