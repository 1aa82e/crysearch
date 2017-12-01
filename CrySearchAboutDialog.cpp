#include "CrySearchAboutDialog.h"
#include "ImlProvider.h"
#include <ide/version.h>

// Include headers to get Capstone version and CrySearch library version.
#include "CrySearchLibrary/SDK/CrySearch.h"
#include "Capstone/include/capstone.h"

// ---------------------------------------------------------------------------------------------

// About dialog constructor.
CrySearchAboutDialog::CrySearchAboutDialog() : CryDialogTemplate(CrySearchIml::AboutButton())
{
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	this->Title(Format("About %s", (char*)appname)).SetRect(0, 0, 450, 300);
	this->mOk <<= THISBACK(CloseAboutWindow);
	
	const DWORD hyperLink[] = { 0x372B5B01, 0x5E5B2030, 0x2E777777, 0x73797263, 0x63726165, 0x6C6E2E68, 0x7243205E, 0x61655379, 0x20686372, 0x73626557, 0x5D657469, 0x5D };
	
	// Set the link to the forum thread of CrySearch.
	this->websiteLink[0] = 0x70747468;
	this->websiteLink[1] = 0x772F2F3A;
	this->websiteLink[2] = 0x632E7777;
	this->websiteLink[3] = 0x65737972;
	this->websiteLink[4] = 0x68637261;
	this->websiteLink[5] = 0x6C6E2E;
	
	const DWORD uppDesc[] = {0x372B5B01, 0x70532030, 0x61696365, 0x6874206C, 0x736B6E61, 0x206F7420, 0x20656874, 0x65766564, 0x65706F6C, 0x65742072, 0x6F206D61, 0x005D2066};
	const DWORD uppLinkDesc[] = { 0x372B5B01, 0x5E5B2030, 0x2E777777, 0x69746C75, 0x6574616D, 0x6F2E7070, 0x205E6772, 0x69746C55, 0x6574616D, 0x012B2B01, 0x00005D5D };
	
	// Set the link to the home page of U++.
	this->uppLink[0] = 0x70747468;
	this->uppLink[1] = 0x772F2F3A;
	this->uppLink[2] = 0x752E7777;
	this->uppLink[3] = 0x6D69746C;
	this->uppLink[4] = 0x70657461;
	this->uppLink[5] = 0x726F2E70;
	this->uppLink[6] = 0x00000067;
	
	// Retrieve CPUID for the primary processor in the host system.
	char info[128];
	GetProcessorSupportInformation(info);
	
	// Retrieve CrySearch version information from backend library.
	char msg[512];
	DWORD sz = 512;
	CrySearchGetVersion(msg, &sz);
	
	*this
		<< this->mProgramImage.SetImage(CrySearchIml::CrySearch()).LeftPos(5, 64).TopPos(5, 64)
		<< this->mProgramInformation.SetLabel(t_(msg)).HSizePos(80, 5).TopPos(2, 75)
		<< this->mLinkLabel.SetLabel(t_((char*)hyperLink)).HSizePos(80, 200).TopPos(70, 25)
		<< this->mProcessorSupportLabel.SetLabel(info).HSizePos(80, 5).TopPos(100, 60)
		<< this->mUppLinkDescription.SetLabel(t_((char*)uppDesc)).HSizePos(80, 80).TopPos(155, 35)
		<< this->mUppLinkLabel.SetLabel(t_((char*)uppLinkDesc)).HSizePos(80, 200).BottomPos(90, 25)
		<< this->mLibraryVersions.HSizePos(80, 70).BottomPos(5, 75)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 25)
	;
	
	// Set up library runtime versions array control.
	this->mLibraryVersions.CryAddColumn("Library");
	this->mLibraryVersions.CryAddColumn("Version");
	
	// Add the revision (version) of U++ used to compile CrySearch to the versions control.
	this->mLibraryVersions.Add("Ultimate++", IDE_VERSION);

	// Add BeaEngine library version to the versions control.
	int major, minor;
	cs_version(&major, &minor);
	this->mLibraryVersions.Add("Capstone", Format("%i.%i", major, minor));
	
	// Set up callbacks to make it possible to resolve the clickable links to its webpage.
	this->mLinkLabel.WhenLeftUp = callback1(LaunchWebBrowser, (char*)this->websiteLink);
	this->mUppLinkLabel.WhenLeftUp = callback1(LaunchWebBrowser, (char*)this->uppLink);
}

// About dialog destructor.
CrySearchAboutDialog::~CrySearchAboutDialog()
{
	
}

// Closes the about dialog.
void CrySearchAboutDialog::CloseAboutWindow()
{
	this->Close();
}