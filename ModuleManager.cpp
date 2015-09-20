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
	result = CrySearchRoutines.RtlQueryProcessDebugInformation(procID, mMemoryScanner->IsX86Process() ? PDI_WOW64_MODULES : PDI_MODULES, db);
#else
	result = CrySearchRoutines.RtlQueryProcessDebugInformation(procID, PDI_MODULES, db);
#endif
	}
	
	if (result != STATUS_SUCCESS || !db->Modules)
	{
		CrySearchRoutines.RtlDestroyQueryDebugBuffer(db);
		return false;
	}
	
	// Walk and save the enumerated modules.
	PDEBUG_MODULE_INFORMATIONEX modInfo = (PDEBUG_MODULE_INFORMATIONEX)db->Modules;
	outModules.Reserve(modInfo->Count);
	for (unsigned int i = 0; i < modInfo->Count; ++i)
	{
		Win32ModuleInformation& curMod = outModules.Add();
		curMod.BaseAddress = modInfo->DbgModInfo[i].Base;
		curMod.Length = modInfo->DbgModInfo[i].Size;
	}
	
	// Free the allocated debug buffer.
	CrySearchRoutines.RtlDestroyQueryDebugBuffer(db);
	
	return true;
}

ModuleManager::ModuleManager()
{
	
}

ModuleManager::~ModuleManager()
{
	
}

// Initializes the internal module store.
void ModuleManager::InitModulesList()
{
	// Clear previous modules from the list.
	this->mLoadedModulesList.Clear();
	
	// Fill the internal module list with the loaded modules inside the target process.
	ModuleManager::EnumerateModules(mMemoryScanner->GetProcessId(), this->mLoadedModulesList);
}

// Resets the module list and retrieves modules from scratch.
void ModuleManager::Initialize()
{
	this->InitModulesList();
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
	const int count = this->mLoadedModulesList.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const Win32ModuleInformation& mod = this->mLoadedModulesList[i];
		if (address >= mod.BaseAddress && address < mod.BaseAddress + mod.Length)
		{
			return &mod;
		}
	}
	
	return NULL;
}

// Retrieves a module in the module manager using its name. NULL if the module is not found.
const Win32ModuleInformation* ModuleManager::FindModule(const char* modName) const
{
	const int count = this->mLoadedModulesList.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const Win32ModuleInformation& mod = this->mLoadedModulesList[i];
		if (_stricmp(this->GetModuleFilename(mod.BaseAddress), modName) == 0)
		{
			return &mod;
		}
	}
	
	return NULL;
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