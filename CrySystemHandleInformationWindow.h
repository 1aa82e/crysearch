#ifndef _CrySearch_CrySystemHandleInformationWindow_h_
#define _CrySearch_CrySystemHandleInformationWindow_h_

#include "CrySearchArrayCtrl.h"
#include "CryDialogTemplate.h"

// When a process is opened, all system handles associated with it can be displayed inside this window.
class CrySystemHandleInformationWindow : public CryDialogTemplate
{
private:
	Button mOK;
	CrySearchArrayCtrl mOpenHandles;
	Label mTotalHandles;
	
	void HandlesListWhenBar(Bar& pBar);
	
	void ViewAccessButtonClicked();
	void CloseRemoteHandleClicked();
	void CloseButtonClicked();
	void Initialize();
	
	typedef CrySystemHandleInformationWindow CLASSNAME;
public:
	CrySystemHandleInformationWindow(const Image& icon);
	~CrySystemHandleInformationWindow();
};

#endif