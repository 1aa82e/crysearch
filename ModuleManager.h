#ifndef _CrySearch_ModuleManager_h_
#define _CrySearch_ModuleManager_h_

#include <Core/Core.h>

using namespace Upp;

#include "ProcessUtil.h"

// Takes care of application-lifetime management and access to/off modules in the remote process.
class ModuleManager
{
private:
	Index<Win32ModuleInformation> mLoadedModulesList;
	SIZE_T lowestAddress;
	SIZE_T highestAddress;

	// Singleton code: private constructor, destructor and copy constructors.
	ModuleManager();
	~ModuleManager();
	
	ModuleManager(ModuleManager const&);
	void operator=(ModuleManager const&);
	
	const bool InitModulesList();
	
#ifdef _WIN64
	const int FindModuleIndex(const char* modName) const;
#endif
public:
	static ModuleManager* GetInstance()
	{
		static ModuleManager instance;
		return &instance;
	}
	
	static const bool EnumerateModules(const int procID, Index<Win32ModuleInformation>& outModules, SIZE_T* lowerBound, SIZE_T* upperBound);
	
	void ClearModules();
	const bool Initialize();

#ifdef _WIN64
	void RemoveNonWow64Modules();
#endif
	
	const SIZE_T GetBaseAddress() const;
	const int GetModuleCount() const;
	const Win32ModuleInformation* GetModuleFromContainedAddress(const SIZE_T address) const;
	const Win32ModuleInformation* FindModule(const char* modName) const;
	String GetModuleFilename(const SIZE_T mod) const;
	const SIZE_T GetLowerBoundAddress() const;
	const SIZE_T GetUpperBoundAddress() const;
	
	const Win32ModuleInformation& operator [] (const int x) const
	{
		return this->mLoadedModulesList[x];
	};
};

#endif