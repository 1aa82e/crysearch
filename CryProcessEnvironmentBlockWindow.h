#ifndef _CrySearch_CryProcessEnvironmentBlockWindow_h_
#define _CrySearch_CryProcessEnvironmentBlockWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class CryProcessEnvironmentBlockWindow sealed : public TopWindow
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
	
	virtual bool Key(dword key, int count);
	
	typedef CryProcessEnvironmentBlockWindow CLASSNAME;
public:
	CryProcessEnvironmentBlockWindow();
	~CryProcessEnvironmentBlockWindow();	
};

#endif
