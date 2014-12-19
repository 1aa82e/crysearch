#include "PluginSystem.h"

// ---------------------------------------------------------------------------------------------

PluginSystem::PluginSystem()
{
	// If the directory plugins is not present, it should be created.
	// However, if it already exists, this function will do nothing.
#ifdef _WIN64
	RealizeDirectory("plugins\\x64\\");
#else
	RealizeDirectory("plugins\\x86\\");
#endif
}

PluginSystem::~PluginSystem()
{
	this->UnloadAllPlugins();
}

// Returns the amount of plugins loaded by CrySearch.
const int PluginSystem::GetPluginCount() const
{
	return this->mLoadedPlugins.GetCount();
}

// Finds a plugin by name and returns its index.
// Returns -1 if the plugin was not found.
const int PluginSystem::FindPlugin(const char* const pName) const
{
	const int count = this->mLoadedPlugins.GetCount();
	for (int i = 0; i < count; ++i)
	{
		if (strcmp(this->mLoadedPlugins[i].PluginHeader->PluginName, pName) == 0)
		{
			return i;
		}
	}
	
	return -1;
}

// Finds out whether a plugin is loaded or not.
// Returns the name of the plugin if it is loaded or NULL otherwise.
const char* PluginSystem::IsPluginLoaded(HMODULE hModule) const
{
	for (int i = 0; i < this->mLoadedPlugins.GetCount(); ++i)
	{
		if (this->mLoadedPlugins[i].BaseAddress == hModule)
		{
			return this->mLoadedPlugins[i].PluginHeader->PluginName;
		}
	}
	
	return NULL;
}

// Retrieves all plugins that comply to the specified type constraint.
// The list that is used as parameter is not cleared. Items are appended.
void PluginSystem::GetPluginsByType(const DWORD type, Vector<CrySearchPlugin>& outPlugins) const
{
	const int count = this->mLoadedPlugins.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const CrySearchPlugin& plugin = this->mLoadedPlugins[i];
		if (plugin.PluginHeader->PluginType & type)
		{
			outPlugins.Add(plugin);
		}
	}
}

// Sends a plugin event to all loaded plugins. The type of event and parameter pointer is to be
// specified through the parameters. The parameter pointer memory is not being managed!
void PluginSystem::SendGlobalPluginEvent(CCryPluginEvent evt, void* const data)
{
	const int count = this->mLoadedPlugins.GetCount();
	for (int i = 0; i < count; ++i)
	{
		// Retrieve a pointer to the event procedure of the current iterated plugin.
		CryProcessPluginEventProc eventProc = (CryProcessPluginEventProc)GetProcAddress(this->mLoadedPlugins[i].BaseAddress, "CryProcessPluginEvent");
		if (eventProc)
		{
			// Execute the procedure.
			eventProc(evt, data);
		}
	}
}

// Retrieves the first dumper engine plugin that has the PLUGIN_DEFAULT_DUMPER flag set.
// Returns the base address of the plugin library or NULL if no dumper engines have this flag set.
HMODULE PluginSystem::GetDefaultDumperEnginePlugin() const
{
	HMODULE tempretifno = NULL;
	const int pCount = this->mLoadedPlugins.GetCount();
	for (int i = 0; i < pCount; ++i)
	{
		const CrySearchPlugin& plugin = this->mLoadedPlugins[i];
		if (plugin.PluginHeader->PluginType & CRYPLUGIN_DUMPER)
		{
			tempretifno = plugin.BaseAddress;
			if (plugin.PluginHeader->Flags & PLUGIN_CLASS_DEFAULT)
			{
				return plugin.BaseAddress;
			}
		}
	}
	
	return tempretifno;
}

// Attempts to unload all plugins that are loaded.
void PluginSystem::UnloadAllPlugins()
{
	for (int i = 0; i < this->mLoadedPlugins.GetCount(); ++i)
	{
		this->UnloadPlugin(this->mLoadedPlugins[i].PluginHeader->PluginName);
	}
}

// Creates a list of plugins in the plugins folder and tries to load every one of them.
void PluginSystem::RetrieveAndLoadAllPlugins()
{
	FindFile searcher;

#ifdef _WIN64
	bool canIterate = searcher.Search("plugins/x64/*.dll");
#else
	bool canIterate = searcher.Search("plugins/x86/*.dll");
#endif
	
	// try to load plugins in the plugins folder.
	while (canIterate)
	{
		// Try to load the plugin.
		this->LoadPlugin(searcher.GetPath());
		
		// Go to the next file.
		canIterate = searcher.Next();
	}
}

// Loads a single plugin by file path.
bool PluginSystem::LoadPlugin(const char* pName)
{
	// Load the library at pName path.
	HMODULE modBase;
	if (modBase = LoadLibrary(pName))
	{
		// Execute the initialization function that the plugin implemented.
		CryInitializePluginProc pCIP = (CryInitializePluginProc)GetProcAddress(modBase, "CryInitializePlugin");
		if (!pCIP)
		{
			return false;
		}
		
		// Initialize the plugin.
		if (pCIP())
		{
			// Retrieve information about the newly loaded plugin.
			CryGetPluginInformationProc pGPI = (CryGetPluginInformationProc)GetProcAddress(modBase, "CryGetPluginInformation");
			
			if (!pGPI)
			{
				return false;
			}
			
			// Retrieve information about the plugin and store it in CrySearch's own store.
			CrySearchPlugin plugin;
			pGPI(&plugin.PluginHeader);
			
			// Multiple plugins with the same name are not allowed.
			if (this->FindPlugin(plugin.PluginHeader->PluginName) >= 0)
			{
				return !this->UnloadPlugin(plugin.PluginHeader->PluginName);
			}
			
			plugin.BaseAddress = modBase;
			this->mLoadedPlugins.Add(plugin);
			
			return true;
		}
	}
	
	return false;
}

// Unloads a single plugin by its friendly name.
bool PluginSystem::UnloadPlugin(const char* pName)
{
	const int pluginIndex = this->FindPlugin(pName);
	const CrySearchPlugin& plugin = this->mLoadedPlugins[pluginIndex];
	CryDestroyPluginProc pCDP = (CryDestroyPluginProc)GetProcAddress(plugin.BaseAddress, "CryDestroyPlugin");
	
	if (!pCDP)
	{
		return false;
	}
	
	// Destroy and unload the plugin.
	pCDP();
	
	// Free the library.
	if (FreeLibrary(plugin.BaseAddress))
	{
		this->mLoadedPlugins.Remove(pluginIndex);
		return true;
	}
	
	return false;
}