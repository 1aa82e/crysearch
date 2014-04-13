#ifndef _CrySearch_CrySystemHandleInformationWindow_h_
#define _CrySearch_CrySystemHandleInformationWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CrySearchArrayCtrl.h"

class CrySystemHandleInformationWindow sealed : public TopWindow
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
	CrySystemHandleInformationWindow();
	~CrySystemHandleInformationWindow();
};

#endif