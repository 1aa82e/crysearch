#ifndef _CrySearch_ThreadChangePriorityWindow_h_
#define _CrySearch_ThreadChangePriorityWindow_h_

#include "CryDialogTemplate.h"

class CryThreadChangePriorityWindow : public CryDialogTemplate
{
private:
	int threadID;
	
	Label priorDesc;
	DropList priorSelect;
	Button mOK;
	Button mCancel;
	
	void OkButton();
	void CancelButton();
	
	typedef CryThreadChangePriorityWindow CLASSNAME;
public:
	CryThreadChangePriorityWindow(const int threadId, const int current, const Image& icon);
	~CryThreadChangePriorityWindow();	
};

#endif
