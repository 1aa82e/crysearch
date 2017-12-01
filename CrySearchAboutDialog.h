#ifndef _CrySearch_AboutCrySearchDialog_h_
#define _CrySearch_AboutCrySearchDialog_h_

#include "CryDialogTemplate.h"
#include "CryClickLabel.h"
#include "CrySearchArrayCtrl.h"

// Simple about dialog for CrySearch, displaying its version, architecture and credits.
class CrySearchAboutDialog : public CryDialogTemplate
{
private:
	DWORD websiteLink[6];
	DWORD uppLink[7];
	ImageCtrl mProgramImage;
	Label mProgramInformation;
	CryClickLabel mLinkLabel;
	Label mProcessorSupportLabel;
	Label mUppLinkDescription;
	CryClickLabel mUppLinkLabel;
	CrySearchArrayCtrl mLibraryVersions;
	Button mOk;
	
	void CloseAboutWindow();
public:
	CrySearchAboutDialog();
	~CrySearchAboutDialog();
	
	typedef CrySearchAboutDialog CLASSNAME;
};

#endif
