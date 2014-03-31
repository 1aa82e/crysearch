#ifndef _CrySearch_CryThreadInformationBlockWindow_h_
#define _CrySearch_CryThreadInformationBlockWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class CryThreadInformationBlockWindow sealed : public TopWindow
{
private:
	Label mThreadWindowDescription;
	ArrayCtrl mThreadInfo;
	Button mOk;
	
	void DialogClose();
	
	virtual bool Key(dword key, int count);
	
	typedef CryThreadInformationBlockWindow CLASSNAME;
public:
	CryThreadInformationBlockWindow(const int threadId);
	~CryThreadInformationBlockWindow();	
};

#endif
