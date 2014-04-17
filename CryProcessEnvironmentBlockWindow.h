#ifndef _CrySearch_CryProcessEnvironmentBlockWindow_h_
#define _CrySearch_CryProcessEnvironmentBlockWindow_h_

#include "CryDialogTemplate.h"

class CryProcessEnvironmentBlockWindow sealed : public CryDialogTemplate
{
private:
	BYTE* pIsBeingDebuggedPtr;

	Label mPEBWindowDescription;
	ArrayCtrl mPEBInfo;
	Button mOk;
	Button mResetDebugFlag;
	
	void Initialize();
	void DialogClose();
	void ResetDebugFlag();
	
	typedef CryProcessEnvironmentBlockWindow CLASSNAME;
public:
	CryProcessEnvironmentBlockWindow();
	~CryProcessEnvironmentBlockWindow();	
};

#endif
