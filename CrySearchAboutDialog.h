#ifndef _CrySearch_AboutCrySearchDialog_h_
#define _CrySearch_AboutCrySearchDialog_h_

#pragma warning(disable : 4005)

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CryClickLabel.h"

// Simple about dialog for CrySearch, displaying its version, architecture and credits.
class CrySearchAboutDialog sealed : public TopWindow
{
private:
	DWORD forumLink[27];
	DWORD uppLink[7];
	ImageCtrl mProgramImage;
	Label mProgramInformation;
	CryClickLabel mLinkLabel;
	Label mProcessorSupportLabel;
	Label mUppLinkDescription;
	CryClickLabel mUppLinkLabel;
	Button mOk;
	
	void CloseAboutWindow();

	virtual bool Key(dword key, int count);
public:
	CrySearchAboutDialog();
	
	typedef CrySearchAboutDialog CLASSNAME;
};

#endif
