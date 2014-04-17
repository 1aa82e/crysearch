#ifndef _CrySearch_CryThreadInformationBlockWindow_h_
#define _CrySearch_CryThreadInformationBlockWindow_h_

#include "CryDialogTemplate.h"

class CryThreadInformationBlockWindow sealed : public CryDialogTemplate
{
private:
	Label mThreadWindowDescription;
	ArrayCtrl mThreadInfo;
	Button mOk;
	
	void DialogClose();
	
	typedef CryThreadInformationBlockWindow CLASSNAME;
public:
	CryThreadInformationBlockWindow(const int threadId);
	~CryThreadInformationBlockWindow();	
};

#endif
