#ifndef _CrySearch_CrySystemHandleAccessMaskWindow_h_
#define _CrySearch_CrySystemHandleAccessMaskWindow_h_

#include "CryDialogTemplate.h"

class CrySystemHandleAccessMaskWindow sealed : public CryDialogTemplate
{
private:
	ArrayCtrl mAccessConstants;
	Button mClose;
	
	void FormClose();
	
	typedef CrySystemHandleAccessMaskWindow CLASSNAME;
public:
	CrySystemHandleAccessMaskWindow(const String& type, const DWORD mask, const Image& icon);
	~CrySystemHandleAccessMaskWindow();
};

#endif