#ifndef _CrySearch_CryHeapWalkDialog_h_
#define _CrySearch_CryHeapWalkDialog_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class CryHeapWalkDialog sealed : public TopWindow
{
private:
	Button mClose;
	ArrayCtrl mHeapList;
	
	void CloseDialog();
	
	virtual bool Key(dword key, int count);
	
	typedef CryHeapWalkDialog CLASSNAME;
public:
	CryHeapWalkDialog();
	~CryHeapWalkDialog();	
};

#endif
