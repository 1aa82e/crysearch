#include "CryPluginsWindow.h"
#include "BackendGlobalDef.h"
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
		<< this->mPluginsList.HSizePos(5, 5).VSizePos(5, 35)
		<< this->mPluginCount.LeftPos(5, 150).BottomPos(5, 25)
		<< this->mOK.Ok().SetLabel("Close").RightPos(5, 60).BottomPos(5, 25)
	;
	
	const int pCount = mPluginSystem->GetPluginCount();
	this->mPluginsList.SetVirtualCount(pCount);
	this->mPluginCount.SetLabel(Format("Total %i plugins", pCount));
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
	const CrySearchPlugin& selected = (*mPluginSystem)[this->mPluginsList.GetCursor()];
	Prompt(Format("About %s", selected.PluginHeader->PluginName), CtrlImg::information(), selected.ShowAboutDialog(), "OK");
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