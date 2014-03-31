#ifndef _CrySearch_CryThreadWindow_h_
#define _CrySearch_CryThreadWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#pragma warning(disable : 4005)

#include "CrySearchArrayCtrl.h"

class CryThreadWindow sealed : public ParentCtrl
{
private:
	ToolBar tBar;
	CrySearchArrayCtrl mThreads;
	
	void ToolBar(Bar& pBar);
	void ThreadListRightClick(Bar& pBar);
	
	void LoadThreads();
	void CreateExternalThread();
	void AttemptSuspendAllThreads();
	void AttemptResumeAllThreads();
	void SuspendThread();
	void ResumeThread();
	void ChangePriority();
	void TerminateThread();
	void ShowThreadInformationWindow();
	
	typedef CryThreadWindow CLASSNAME;
public:
	CryThreadWindow();
	~CryThreadWindow();
	
	void Initialize();
	void ClearList();
};

#endif
