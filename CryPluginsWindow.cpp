#include "CryPluginsWindow.h"
#include "GlobalDef.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

String GetPluginName(const int index)
{
	return (*mPluginSystem)[index].PluginHeader->PluginName;
}

String GetPluginFilename(const int index)
{
	char fn[MAX_PATH];
	GetModuleFileName((*mPluginSystem)[index].BaseAddress, fn, MAX_PATH);
	return GetFileName(fn);
}

String GetPluginVersion(const int index)
{
	return Format("%i.%i", (*mPluginSystem)[index].PluginHeader->MajorVersion, (*mPluginSystem)[index].PluginHeader->MinorVersion);
}

// ---------------------------------------------------------------------------------------------

CryPluginsWindow::CryPluginsWindow() : CryDialogTemplate(CrySearchIml::PluginsMenuSmall())
{
	this->Title("Plugins").Sizeable().SetRect(0, 0, 500, 300);
	
	this->mOK <<= THISBACK(CloseWindow);
	
	this->mPluginsList.CryAddRowNumColumn("Name", 45).SetConvert(Single<IndexBasedValueConvert<GetPluginName>>());
	this->mPluginsList.CryAddRowNumColumn("Filename", 40).SetConvert(Single<IndexBasedValueConvert<GetPluginFilename>>());
	this->mPluginsList.CryAddRowNumColumn("Version", 15).SetConvert(Single<IndexBasedValueConvert<GetPluginVersion>>());
	this->mPluginsList.WhenBar = THISBACK(PluginRightClick);
	
	*this
		<< this->mPluginsList.HSizePos(5, 5).VSizePos(5, 30)
		<< this->mPluginCount.LeftPos(5, 150).BottomPos(5, 20)
		<< this->mOK.Ok().SetLabel("Close").RightPos(5, 60).BottomPos(5, 20)
	;
	
	this->mPluginsList.SetVirtualCount(mPluginSystem->GetPluginCount());
	this->mPluginCount.SetLabel(Format("Total %i plugins", mPluginSystem->GetPluginCount()));
}

CryPluginsWindow::~CryPluginsWindow()
{
	
}

void CryPluginsWindow::PluginRightClick(Bar& pBar)
{
	const int row = this->mPluginsList.GetCursor();
	if (row >= 0 && mPluginSystem->GetPluginCount())
	{
		pBar.Add("About", CrySearchIml::AboutButton(), THISBACK(ShowPluginAbout));
		pBar.Add("Unload", CrySearchIml::DeleteButton(), THISBACK(UnloadPluginButton));
	}
}

void CryPluginsWindow::ShowPluginAbout()
{
	const int row = this->mPluginsList.GetCursor();
	PromptOK((*mPluginSystem)[row].ShowAboutDialog());
}

void CryPluginsWindow::UnloadPluginButton()
{
	const int row = this->mPluginsList.GetCursor();
	mPluginSystem->UnloadPlugin((*mPluginSystem)[row].PluginHeader->PluginName);
	this->mPluginsList.SetVirtualCount(mPluginSystem->GetPluginCount());
	this->mPluginCount.SetLabel(Format("Total %i plugins", mPluginSystem->GetPluginCount()));
}

void CryPluginsWindow::CloseWindow()
{
	this->Close();
}