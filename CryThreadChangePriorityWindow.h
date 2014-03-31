#ifndef _CrySearch_ThreadChangePriorityWindow_h_
#define _CrySearch_ThreadChangePriorityWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class ThreadChangePriorityWindow sealed : public TopWindow
{
private:
	int threadID;
	
	Label priorDesc;
	DropList priorSelect;
	Button mOK;
	Button mCancel;
	
	void OkButton();
	void CancelButton();
	
	typedef ThreadChangePriorityWindow CLASSNAME;
public:
	ThreadChangePriorityWindow(const int threadId, const int current);
	~ThreadChangePriorityWindow();	
};

#endif
