#include "ModuleManager.h"
#include "BackendGlobalDef.h"

#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

// Retrieves all modules loaded from a process including base and size.
const bool ModuleManager::EnumerateModules(const int procID, Vector<Win32ModuleInformation>& outModules)
{
	// Create debug buffer to hold heap information.
	PRTL_DEBUG_INFORMATION db = CrySearchRoutines.RtlCreateQueryDebugBuffer(0, FALSE);
	if (!db)
	{
		return false;
	}

	// Get heap information and put it inside the debug buffer.
	NTSTATUS result;
	if (procID == GetCurrentProcessId())
	{
		result = CrySearchRoutines.RtlQueryProcessDebugInformation(procID, PDI_MODULES, db);
	}
	else
	{
#ifdef _WIN64
	// We need non-invasiveness in order to have the system call succeed; I didn't find any other way of succesfully retrieving wow64 modules.
	result = CrySearchRoutines.RtlQueryProcessDebugInformation(procID, mMemoryScanner->IsX86Process() ? PDI_WOW64_MODULES | PDI_NONINVASIVE : PDI_MODULES, db);
#else
	result = CrySearchRoutines.RtlQueryProcessDebugInformation(procID, PDI_MODULES, db);
#endif
	}
	
	// Failed to query module information properly.
	if (result != STATUS_SUCCESS || !db->Modules)
	{
		CrySearchRoutines.RtlDestroyQueryDebugBuffer(db);
		return false;
	}
	
	// Walk and save the enumerated modules.
	PDEBUG_MODULES_STRUCT modInfo = db->Modules;
	outModules.Reserve(modInfo->Count);
	for (unsigned int i = 0; i < modInfo->Count; ++i)
	{
		Win32ModuleInformation& curMod = outModules.Add();
		curMod.BaseAddress = (SIZE_T)modInfo->DbgModInfo[i].ImageBase;
		curMod.Length = modInfo->DbgModInfo[i].ImageSize;
	}
	
	// Free the allocated debug buffer.
	CrySearchRoutines.RtlDestroyQueryDebugBuffer(db);
	
	return true;
}

// Default ModuleManager constructor.
ModuleManager::ModuleManager()
{
	
}

// Default ModuleManager destructor.
ModuleManager::~ModuleManager()
{
	
}

// Initializes the internal module store.
const bool ModuleManager::InitModulesList()
{
	// Clear previous modules from the list.
	this->mLoadedModulesList.Clear();
	
	// Fill the internal module list with the loaded modules inside the target process.
	return ModuleManager::EnumerateModules(mMemoryScanner->GetProcessId(), this->mLoadedModulesList);
}

// Resets the module list and retrieves modules from scratch.
const bool ModuleManager::Initialize()
{
	return this->InitModulesList();
}

// Clears the module list.
void ModuleManager::ClearModules()
{
	this->mLoadedModulesList.Clear();
}

// Retrieves the base address of the opened process.
const SIZE_T ModuleManager::GetBaseAddress() const
{
	return this->mLoadedModulesList.GetCount() > 0 ? this->mLoadedModulesList[0].BaseAddress : 0;
}

// Retrieves the amount of modules in the opened process.
const int ModuleManager::GetModuleCount() const
{
	return this->mLoadedModulesList.GetCount();
}

// Retrieves a pointer to the module that contains the specified address. NULL if no module does.
const Win32ModuleInformation* ModuleManager::GetModuleFromContainedAddress(const SIZE_T address) const
{
	for (auto const& mod : this->mLoadedModulesList)
	{
		if (address >= mod.BaseAddress && address < mod.BaseAddress + mod.Length)
		{
			return &mod;
		}
	}
	
	return NULL;
}

// Retrieves the first instance of a module in the module manager using its name.
// Returns NULL if the module is not found.
const Win32ModuleInformation* ModuleManager::FindModule(const char* modName) const
{
	for (auto const& mod : this->mLoadedModulesList)
	{
		if (_stricmp(this->GetModuleFilename(mod.BaseAddress), modName) == 0)
		{
			return &mod;
		}
	}
	
	return NULL;
}

// Retrieves the index of the first instance of a module in the module manager using its name.
// Returns -1 if the module was not found.
const int ModuleManager::FindModuleIndex(const char* modName) const
{
	const int count = this->mLoadedModulesList.GetCount();
	for (int i = 0; i < count; ++i)
	{
		if (_stricmp(this->GetModuleFilename(this->mLoadedModulesList[i].BaseAddress), modName) == 0)
		{
			return i;
		}
	}
	
	return -1;
}

// Retrieves the module filename of a loaded module in the process. Returns an empty string if
// the retrieval of the filename failed.
String ModuleManager::GetModuleFilename(const SIZE_T mod) const
{
	StringBuffer buffer(MAX_PATH);
	GetModuleFileNameEx(mMemoryScanner->GetHandle(), (HMODULE)mod, buffer.Begin(), MAX_PATH);
	buffer.Strlen();
	return GetFileNamePos(buffer.Begin());
}

#ifdef _WIN64
	// Removes all non-wow64 modules from the internal list.
	void ModuleManager::RemoveNonWow64Modules()
	{
		const int count = this->mLoadedModulesList.GetCount();
		
		// Unless the user manually hid the image name, there should be two instances of the image name.
		// Find them, and if there are two, remove the first one.
		const String imageName = this->GetModuleFilename(NULL);
		int first = -1;
		for (int j = 0; j < count; ++j)
		{
			if (_stricmp(this->GetModuleFilename(this->mLoadedModulesList[j].BaseAddress), imageName) == 0)
			{
				if (first == -1)
				{
					first = j;
				}
				else
				{
					// Second module found, remove the first occurence and bail.
					this->mLoadedModulesList.Remove(first);
					first = -1;
					break;
				}
			}
		}
		
		// If only one module with the image name was found, the user has hidden the valid one.
		// Let's just remove the one module we found.
		if (first == 0)
		{
			this->mLoadedModulesList.Remove(first);
		}
		
		// Remove conflicting ntdll.dll instance.
		for (int i = 0; i < count; ++i)
		{
			if (_stricmp(this->GetModuleFilename(this->mLoadedModulesList[i].BaseAddress), "ntdll.dll") == 0)
			{
				// Check whether the address overflows a 32-bit integer (wow64 address space limitations).
				if (this->mLoadedModulesList[i].BaseAddress / 4294967296 > 0)
				{
					this->mLoadedModulesList.Remove(i);
					break;
				}
			}
		}
		
		// Remove the known wow64 modules from the list.
		const int wow64 = this->FindModuleIndex("wow64.dll");
		if (wow64 != -1)
		{
			this->mLoadedModulesList.Remove(wow64);
		}
		
		const int wow64win = this->FindModuleIndex("wow64win.dll");
		if (wow64win != -1)
		{
			this->mLoadedModulesList.Remove(wow64win);
		}
		
		const int wow64cpu = this->FindModuleIndex("wow64cpu.dll");
		if (wow64cpu != -1)
		{
			this->mLoadedModulesList.Remove(wow64cpu);
		}
	}
#endif