#ifndef _CrySearch_SettingsFile_h_
#define _CrySearch_SettingsFile_h_

#include <Core/Core.h>

using namespace Upp;

// Thread priority definitions. Using macros due to enum compilation issues.
#define PRIORITY_LOWEST			0
#define PRIORITY_BELOWNORMAL	1
#define PRIORITY_NORMAL			2
#define PRIORITY_ABOVENORMAL 	3
#define PRIORITY_HIGHEST		4

// Routine definitions. Using macros due to enum compilation issues.
#define ROUTINE_OPENPROCESS				0
#define ROUTINE_NTOPENPROCESS			1

#define ROUTINE_READPROCESSMEMORY		0
#define ROUTINE_NTREADVIRTUALMEMORY		1

#define ROUTINE_WRITEPROCESSMEMORY		0
#define ROUTINE_NTWRITEVIRTUALMEMORY	1

#define ROUTINE_VIRTUALPROTECTEX		0
#define ROUTINE_NTPROTECTVIRTUALMEMORY	1

// Library injection method definitions. Using macros due to enum compilation issues.
#define INJECTION_METHOD_CRT			0
#define INJECTION_METHOD_HIJACKTHREAD	1

// Represents a hotkey that can be used to shorten up actions in CrySearch.
struct CrySearchHotKey : Moveable<CrySearchHotKey>
{
	int Key;
	String Description;
	Callback Action;
	
	void Xmlize(XmlIO& pXml)
	{
		pXml
			("Key", this->Key)
			("Description", this->Description)
		;
	};
};

// Represents the application settings manager
class SettingsFile
{
private:
	int mLanguage;
	DWORD obfuscation[4];
	
	bool mFastScanByDefault;
	int mScanningThreadPriority;
	
	bool mScanWritableMemory;
	bool mScanExecutableMemory;
	bool mScanCopyOnWriteMemory;
	
	bool mScanMemPrivate;
	bool mScanMemImage;
	bool mScanMemMapped;
	
	bool mEnableReadOnlyMode;
	
	int mOpenProcessRoutine;
	int mReadMemoryRoutine;
	int mWriteMemoryRoutine;
	int mProtectMemoryRoutine;
	int mAddressTableUpdateInterval;
	int mLibraryInjectionMethod;
	
	int mStackSnapshotLimit;
	bool mAttemptHideDebuggerPeb;
	bool mCatchAllExceptions;
	bool mInvadeProcess;
	Vector<String> mSymbolPaths;
	
	bool mEnableHotkeys;
	Vector<CrySearchHotKey> hotkeys;
	
	int mDissectionUpdateInterval;
	bool mDissectionHexView;
	bool mEnableDissectionTypeGuessing;
	
	SettingsFile();
	~SettingsFile();
	
	SettingsFile(SettingsFile const&);
	void operator=(SettingsFile const&);
public:
	static SettingsFile* GetInstance()
	{
		static SettingsFile instance;
		return &instance;
	}
	
	// inline getters for settings variables
	const bool GetFastScanByDefault() const						{ return this->mFastScanByDefault; }
	
	const bool GetScanWritableMemory() const					{ return this->mScanWritableMemory; }
	const bool GetScanExecutableMemory() const					{ return this->mScanExecutableMemory; }
	const bool GetScanCopyOnWriteMemory() const					{ return this->mScanCopyOnWriteMemory; }
	
	const bool GetScanMemPrivate() const						{ return this->mScanMemPrivate; }
	const bool GetScanMemImage() const							{ return this->mScanMemImage; }
	const bool GetScanMemMapped() const							{ return this->mScanMemMapped; }
	
	const int GetScanThreadPriority() const						{ return this->mScanningThreadPriority; }
	const bool GetEnableReadOnlyMode() const					{ return this->mEnableReadOnlyMode; }
	
	const int GetOpenProcessRoutine() const						{ return this->mOpenProcessRoutine; }
	const int GetReadMemoryRoutine() const						{ return this->mReadMemoryRoutine; }
	const int GetWriteMemoryRoutine() const						{ return this->mWriteMemoryRoutine; }
	const int GetProtectMemoryRoutine() const					{ return this->mProtectMemoryRoutine; }
	const int GetLibraryInjectionMethod() const					{ return this->mLibraryInjectionMethod; }
	
	const int GetStackSnapshotLimit() const						{ return this->mStackSnapshotLimit; }
	const int GetAddressTableUpdateInterval() const				{ return this->mAddressTableUpdateInterval; }
	const bool GetAttemptHideDebuggerFromPeb() const			{ return this->mAttemptHideDebuggerPeb; }
	const bool GetCatchAllExceptions() const					{ return this->mCatchAllExceptions; }
	
	const bool GetEnableHotkeys() const							{ return this->mEnableHotkeys; }
	const bool GetInvadeProcess() const							{ return this->mInvadeProcess; }
	
	const int GetDissectionUpdateInterval() const				{ return this->mDissectionUpdateInterval; }
	const bool GetDissectionHexadecimalView() const				{ return this->mDissectionHexView; }
	const bool GetEnableDissectionTypeGuessing() const			{ return this->mEnableDissectionTypeGuessing; }
	
	// inline setters for settings variables
	void SetFastScanByDefault(bool value = true)				{ this->mFastScanByDefault = value; }
	
	void SetScanWritableMemory(bool value = true)				{ this->mScanWritableMemory = value; }
	void SetScanExecutableMemory(bool value = true)				{ this->mScanExecutableMemory = value; }
	void SetScanCopyOnWriteMemory(bool value = true)			{ this->mScanCopyOnWriteMemory = value; }
	
	void SetScanMemPrivate(bool value = true)					{ this->mScanMemPrivate = value; }
	void SetScanMemImage(bool value = true)						{ this->mScanMemImage = value; }
	void SetScanMemMapped(bool value = true)					{ this->mScanMemMapped = value; }
	
	void SetScanThreadPriority(int value = 2)					{ this->mScanningThreadPriority = value; }
	void SetEnableReadOnlyMode(bool value = false)				{ this->mEnableReadOnlyMode = value; }
	
	void SetOpenProcessRoutine(int value = 0)					{ this->mOpenProcessRoutine = value; }
	void SetReadMemoryRoutine(int value = 0)					{ this->mReadMemoryRoutine = value; }
	void SetWriteMemoryRoutine(int value = 0)					{ this->mWriteMemoryRoutine = value; }
	void SetProtectMemoryRoutine(int value = 0)					{ this->mProtectMemoryRoutine = value; }
	void SetLibraryInjectionMethod(int value = 0)				{ this->mLibraryInjectionMethod = value; }
	
	void SetAddressTableUpdateInterval(int value = 500)			{ this->mAddressTableUpdateInterval = value; }
	void SetAttemptHideDebuggerFromPeb(bool value = true)		{ this->mAttemptHideDebuggerPeb = value; }
	void SetCatchAllExceptions(bool value = false)				{ this->mCatchAllExceptions = value; }
	
	void SetStackSnapshotLimit(int value = 1024)				{ this->mStackSnapshotLimit = value; }
	
	void SetEnableHotkeys(bool value = true)					{ this->mEnableHotkeys = value; }
	void SetInvadeProcess(bool value = true)					{ this->mInvadeProcess = value; }
	
	void SetDissectionUpdateInterval(int value = 500)			{ this->mDissectionUpdateInterval = value; }
	void SetDissectionHexadecimalView(bool value = false)		{ this->mDissectionHexView = value; }
	void SetEnableDissectionTypeGuessing(bool value = false)	{ this->mEnableDissectionTypeGuessing = value; }
	
	// Hotkey list functions
	void AddHotkey(const String& description, unsigned int key);
	void DeleteHotKey(const unsigned int index);
	CrySearchHotKey& GetHotkey(const unsigned int index);
	const unsigned int GetHotkeyCount()	const					{ return this->hotkeys.GetCount(); }
	
	// Symbol path functions
	bool AddSymbolPath(const String& path);
	void DeleteSymbolPath(const int index);
	const String& GetSymbolPath(const int index) const			{ return this->mSymbolPaths[index]; }
	const unsigned int GetSymbolPathCount() const				{ return this->mSymbolPaths.GetCount(); }
	
	bool Initialize();
	void Save();
	void Xmlize(XmlIO& pXml);
	
	void DefaultSettings();
	const char* const GetSettingsFilename() const				{ return (char*)this->obfuscation; }
	
	// Checks wether the application settings file exists or not
	static const bool ConfigFileExists();
};

#endif