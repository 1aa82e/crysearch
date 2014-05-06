#ifndef _CrySearch_PluginSystem_h_
#define _CrySearch_PluginSystem_h_

#include <Core/Core.h>

using namespace Upp;

#include "CrySearchLibrary/SDK/Plugin.h"

// Represents a plugin information block that CrySearch uses to manage its plugins.
struct CrySearchPlugin : Moveable<CrySearchPlugin>
{
	HMODULE BaseAddress;
	PCRYPLUGINHEADER PluginHeader;
};

// Represents the CrySearch plugin system. It manages every plugin in the system.
class PluginSystem sealed
{
private:
	Vector<CrySearchPlugin> mLoadedPlugins;

	// Singleton code: private constructor, destructor and copy constructors.
	PluginSystem();
	~PluginSystem();
	
	PluginSystem(PluginSystem const&);
	void operator=(PluginSystem const&);
public:
	static PluginSystem* GetInstance()
	{
		static PluginSystem instance;
		return &instance;
	}
	
	void RetrieveAndLoadAllPlugins();
	void UnloadAllPlugins();
	
	bool LoadPlugin(const char* pName);
	bool UnloadPlugin(const char* pName);
	
	const int GetPluginCount() const;
	const int FindPlugin(const char* const pName) const;
	const char* IsPluginLoaded(HMODULE hModule) const;
	void GetPluginsByType(const DWORD type, Vector<CrySearchPlugin>& outPlugins) const;
	
	HMODULE GetDefaultDumperEnginePlugin() const;
	
	const CrySearchPlugin& operator[] (const int index) const
	{
		return this->mLoadedPlugins[index];
	};
};

#endif