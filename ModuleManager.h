#ifndef _CrySearch_ModuleManager_h_
#define _CrySearch_ModuleManager_h_

#include <Core/Core.h>

using namespace Upp;

#include "ProcessUtil.h"

// Takes care of application-lifetime management and access to/off modules in the remote process.
class ModuleManager
{
private:
	Vector<Win32ModuleInformation> mLoadedModulesList;

	// Singleton code: private constructor, destructor and copy constructors.
	ModuleManager();
	~ModuleManager();
	
	ModuleManager(ModuleManager const&);
	void operator=(ModuleManager const&);
	
	void EnumerateModules();
public:
	static ModuleManager* GetInstance()
	{
		static ModuleManager instance;
		return &instance;
	}
	
	void ClearModules();
	void Initialize();
	
	const SIZE_T GetBaseAddress() const;
	const int GetModuleCount() const;
	const Win32ModuleInformation* GetModuleFromContainedAddress(const SIZE_T address) const;
	const Win32ModuleInformation* FindModule(const char* modName) const;
	String GetModuleFilename(const SIZE_T mod) const;
	
	const Win32ModuleInformation& operator [] (const int x) const
	{
		return this->mLoadedModulesList[x];
	};
};

#endif