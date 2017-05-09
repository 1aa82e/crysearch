#include "CrySearchAboutDialog.h"
#include "ImlProvider.h"
#include <ide/version.h>

// Because of the BeaEngine declaration the header should be loosely included here.
#include "CrySearchLibrary/SDK/CrySearch.h"

// Overridden BeaEngine function declarations.
extern "C"
{
	const char* __stdcall BeaEngineVersion();
	const char* __stdcall BeaEngineRevision();
};

// ---------------------------------------------------------------------------------------------

// About dialog constructor.
CrySearchAboutDialog::CrySearchAboutDialog() : CryDialogTemplate(CrySearchIml::AboutButton())
{
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	this->Title(Format("About %s", (char*)appname)).SetRect(0, 0, 450, 300);
	this->mOk <<= THISBACK(CloseAboutWindow);
	
	const DWORD hyperLink[] = { 0x372B5B01, 0x5E5B2030, 0x2E777777, 0x6E6B6E75, 0x636E776F, 0x74616568, 0x656D2E73, 0x6E55205E, 0x576F6E4B, 0x6568436E, 0x2E735461, 0x5D5D656D, 0x00000000 };
	
	// Set the link to the forum thread of CrySearch.
	this->forumLink[0] = 0x70747468;
	this->forumLink[1] = 0x772F2F3A;
	this->forumLink[2] = 0x752E7777;
	this->forumLink[3] = 0x6F6E6B6E;
	this->forumLink[4] = 0x68636E77;
	this->forumLink[5] = 0x73746165;
	this->forumLink[6] = 0x2F656d2E;
	this->forumLink[7] = 0x75726F66;
	this->forumLink[8] = 0x65672f6D;
	this->forumLink[9] = 0x6172656E;
	this->forumLink[10] = 0x72702D6C;
	this->forumLink[11] = 0x6172676F;
	this->forumLink[12] = 0x6E696D6D;
	this->forumLink[13] = 0x6E612D67;
	this->forumLink[14] = 0x65722D64;
	this->forumLink[15] = 0x73726576;
	this->forumLink[16] = 0x2F676E69;
	this->forumLink[17] = 0x36303031;
	this->forumLink[18] = 0x632D3737;
	this->forumLink[19] = 0x65737972;
	this->forumLink[20] = 0x68637261;
	this->forumLink[21] = 0x6D656D2D;
	this->forumLink[22] = 0x2D79726F;
	this->forumLink[23] = 0x6E616373;
	this->forumLink[24] = 0x2E72656E;
	this->forumLink[25] = 0x6C6D7468;
	this->forumLink[26] = 0x0;
	
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
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 65).BottomPos(5, 25)
	;
	
	// Set up library runtime versions array control.
	this->mLibraryVersions.CryAddColumn("Library");
	this->mLibraryVersions.CryAddColumn("Version");
	
	// Add the revision (version) of U++ used to compile CrySearch to the versions control.
	this->mLibraryVersions.Add("Ultimate++", IDE_VERSION);

	// Add BeaEngine library version to the versions control.
	this->mLibraryVersions.Add("BeaEngine", Format("%s rev %s", BeaEngineVersion(), BeaEngineRevision()));
	
	// Set up callbacks to make it possible to resolve the clickable links to its webpage.
	this->mLinkLabel.WhenLeftUp = callback1(LaunchWebBrowser, (char*)this->forumLink);
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