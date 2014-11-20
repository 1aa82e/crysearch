#include "ModuleManager.h"
#include "BackendGlobalDef.h"

#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

ModuleManager::ModuleManager()
{
	
}

ModuleManager::~ModuleManager()
{
	
}

// Retrieves all modules loaded from a process including base and size.
void ModuleManager::EnumerateModules()
{
	// Clear previous modules from the list.
	this->mLoadedModulesList.Clear();
	
	// Some processes have so many modules. Better safe than sorry.
	HMODULE* modules = (HMODULE*)VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
	DWORD modulesFound = 0;
	HANDLE hProcess = mMemoryScanner->GetHandle();

#ifdef _WIN64
	EnumProcessModulesEx(hProcess, modules, 1024 * sizeof(HMODULE), &modulesFound, mMemoryScanner->IsX86Process() ? LIST_MODULES_32BIT : LIST_MODULES_64BIT);
#else
	EnumProcessModules(hProcess, modules, 1024 * sizeof(HMODULE), &modulesFound);
#endif
	
	for (unsigned int i = 0; i < modulesFound / sizeof(HMODULE); ++i)
	{
		Win32ModuleInformation curMod;
				
		char dllName[MAX_PATH];
		GetModuleFileNameEx(hProcess, modules[i], dllName, MAX_PATH);
		curMod.ModuleName = GetFileName(dllName);
		
		MODULEINFO modInfo;
		GetModuleInformation(hProcess, modules[i], &modInfo, sizeof(MODULEINFO));
		curMod.Length = modInfo.SizeOfImage;
		curMod.BaseAddress = (SIZE_T)modInfo.lpBaseOfDll;
		
		this->mLoadedModulesList.Add(curMod);
	}

	// Free allocated memory.
	VirtualFree(modules, 0, MEM_RELEASE);
}

// Resets the module list and retrieves modules from scratch.
void ModuleManager::Initialize()
{
	this->EnumerateModules();
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
		if (_stricmp(mod.ModuleName, modName) == 0)
		{
			return &mod;
		}
	}
	
	return NULL;
}