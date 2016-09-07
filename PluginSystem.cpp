#include "PluginSystem.h"

// ---------------------------------------------------------------------------------------------

// Default PluginSystem constructor.
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

// Default PluginSystem destructor.
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
	for (auto const& plugin : this->mLoadedPlugins)
	{
		if (plugin.BaseAddress == hModule)
		{
			return plugin.PluginHeader->PluginName;
		}
	}
	
	return NULL;
}

// Retrieves all plugins that comply to the specified type constraint.
// The list that is used as parameter is not cleared. Items are appended.
void PluginSystem::GetPluginsByType(const DWORD type, Vector<CrySearchPlugin>& outPlugins) const
{
	for (auto const& plugin : this->mLoadedPlugins)
	{
		if (plugin.PluginHeader->PluginFeatures & type)
		{
			outPlugins.Add(plugin);
		}
	}
}

// Sends a plugin event to all loaded plugins. The type of event and parameter pointer is to be
// specified through the parameters. The parameter pointer memory is not being managed!
void PluginSystem::SendGlobalPluginEvent(CCryPluginEvent evt, void* const data)
{
	for (auto const& plugin : this->mLoadedPlugins)
	{
		// Retrieve a pointer to the event procedure of the current iterated plugin.
		CryProcessPluginEventProc eventProc = (CryProcessPluginEventProc)GetProcAddress(plugin.BaseAddress, "CryProcessPluginEvent");
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
	for (auto const& plugin : this->mLoadedPlugins)
	{
		if (plugin.PluginHeader->PluginFeatures & CRYPLUGIN_DUMPER)
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
	for (auto const& plugin : this->mLoadedPlugins)
	{
		this->UnloadPlugin(plugin.PluginHeader->PluginName);
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
				// Unload the library, the plugin cannot be loaded.
				CryDestroyPluginProc pCDP = (CryDestroyPluginProc)GetProcAddress(modBase, "CryDestroyPlugin");
				if (pCDP)
				{
					pCDP();
				}

				FreeLibrary(modBase);

				return false;
			}

			// Add the newly loaded plugin to the list.
			plugin.BaseAddress = modBase;
			this->mLoadedPlugins.Add(plugin);
			
			// If the newly loaded plugin is a core function plugin, check its validity.
			if (plugin.PluginHeader->PluginFeatures & CRYPLUGIN_COREFUNC_OVERRIDE)
			{
				if (!this->IsCorePluginValid(plugin))
				{
					return !this->UnloadPlugin(plugin.PluginHeader->PluginName);
				}
			}
			
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

// Validates the content of a core function plugin, to see if all set flags have
// matching bodies. Returns true if the plugin at modBase is valid and false otherwise.
const bool PluginSystem::IsCorePluginValid(const CrySearchPlugin& plugin) const
{
	bool result = true;
	
	// Check for the memory reading function flag.
	if (plugin.PluginHeader->Flags & PLUGIN_CORE_READ_PROCESS_MEMORY)
	{
		CryReadMemoryRoutineType func = (CryReadMemoryRoutineType)GetProcAddress(plugin.BaseAddress, "CryReadMemoryRoutine");
		if (!func)
		{
			result = false;
		}
	}
	
	// Check for the memory writing function flag.
	if (plugin.PluginHeader->Flags & PLUGIN_CORE_WRITE_PROCESS_MEMORY)
	{
		CryWriteMemoryRoutineType func = (CryWriteMemoryRoutineType)GetProcAddress(plugin.BaseAddress, "CryWriteMemoryRoutine");
		if (!func)
		{
			result = false;
		}
	}
	
	// Check for the memory protection function flag.
	if (plugin.PluginHeader->Flags & PLUGIN_CORE_PROTECT_PROCESS_MEMORY)
	{
		CryProtectMemoryRoutineType func = (CryProtectMemoryRoutineType)GetProcAddress(plugin.BaseAddress, "CryProtectMemoryRoutine");
		if (!func)
		{
			result = false;
		}
	}
	
	// Check for the process opening function flag.
	if (plugin.PluginHeader->Flags & PLUGIN_CORE_OPEN_PROCESS)
	{
		CryOpenProcessRoutineType func = (CryOpenProcessRoutineType)GetProcAddress(plugin.BaseAddress, "CryOpenProcessRoutine");
		if (!func)
		{
			result = false;
		}
	}
	
	return result;
}