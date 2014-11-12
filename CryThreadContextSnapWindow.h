#ifndef _CrySearch_CryThreadContextSnapWindow_h_
#define _CrySearch_CryThreadContextSnapWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Represents the context snap window which displays a context snapshot of a specific thread.
class CryThreadContextSnapWindow : public CryDialogTemplate
{
private:
	int mThreadId;
	
	Button mRefresh;
	Button mClose;
	CrySearchArrayCtrl mContextValues;
	
	void RefreshSnapshot();
	void CloseWindow();
	
	typedef CryThreadContextSnapWindow CLASSNAME;
public:
	CryThreadContextSnapWindow(const Image& icon, const int threadId);
	~CryThreadContextSnapWindow();
};

#endif