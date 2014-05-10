#include "CryPluginsWindow.h"
#include "GlobalDef.h"
#include "ImlProvider.h"

String GetPluginName(const int index)
{
	return (*mPluginSystem)[index].PluginHeader->PluginName;
}

String GetPluginType(const int index)
{
	return GetPluginTypeFriendlyName((*mPluginSystem)[index].PluginHeader->PluginType);
}

String GetPluginVersion(const int index)
{
	return Format("%i.%i", (*mPluginSystem)[index].PluginHeader->MajorVersion, (*mPluginSystem)[index].PluginHeader->MinorVersion);
}

// ---------------------------------------------------------------------------------------------

CryPluginsWindow::CryPluginsWindow() : CryDialogTemplate(CrySearchIml::PluginsMenuSmall())
{
	this->Title("Plugins").SetRect(0, 0, 400, 300);
	
	this->mOK <<= THISBACK(CloseWindow);
	
	this->mPluginsList.AddRowNumColumn("Name", 50).SetConvert(Single<IndexBasedValueConvert<GetPluginName>>());
	this->mPluginsList.AddRowNumColumn("Type", 35).SetConvert(Single<IndexBasedValueConvert<GetPluginType>>());
	this->mPluginsList.AddRowNumColumn("Version", 15).SetConvert(Single<IndexBasedValueConvert<GetPluginVersion>>());
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
		pBar.Add("Unload", CrySearchIml::DeleteButton(), THISBACK(UnloadPluginButton));
	}
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