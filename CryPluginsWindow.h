#ifndef _CrySearch_CryPluginsWindow_h_
#define _CrySearch_CryPluginsWindow_h_

#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Represents the plugin window. It shows information about the loaded plugins.
class CryPluginsWindow : public CryDialogTemplate
{
private:
	Button mOK;	
	CrySearchArrayCtrl mPluginsList;
	Label mPluginCount;
	
	void PluginRightClick(Bar& pBar);
	
	void ShowPluginAbout();
	void UnloadPluginButton();
	void CloseWindow();
	
	typedef CryPluginsWindow CLASSNAME;
public:
	CryPluginsWindow();
	~CryPluginsWindow();
};

#endif