#ifndef _CrySearch_AboutCrySearchDialog_h_
#define _CrySearch_AboutCrySearchDialog_h_

#pragma warning(disable : 4005)

#include "CryDialogTemplate.h"
#include "CryClickLabel.h"

// Simple about dialog for CrySearch, displaying its version, architecture and credits.
class CrySearchAboutDialog sealed : public CryDialogTemplate
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
public:
	CrySearchAboutDialog();
	
	typedef CrySearchAboutDialog CLASSNAME;
};

#endif
