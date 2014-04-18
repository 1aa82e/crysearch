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

// Checks wether the application settings file exists or not
bool ConfigFileExists();

// Represents a hotkey that can be used to shorten up actions in CrySearch.
struct CrySearchHotKey : Moveable<CrySearchHotKey>
{
	int Key;
	String Description;
	Callback1<bool> Action;
	
	void Xmlize(XmlIO& pXml)
	{
		pXml
			("Key", this->Key)
			("Description", this->Description)
		;
	}
};

template <String (GetData) (const unsigned int index)>
struct HotkeyValueConvert : public Convert
{
	virtual Value Format(const Value& q) const
	{
		return GetData(int(q));
	}
};

// Represents the application settings manager
class SettingsFile sealed
{
private:
	int mLanguage;
	
	bool mFastScanByDefault;
	int mScanningThreadPriority;
	
	bool mScanWritableMemory;
	bool mScanExecutableMemory;
	bool mScanCopyOnWriteMemory;
	
	bool mScanMemPrivate;
	bool mScanMemImage;
	bool mScanMemMapped;
	
	int mOpenProcessRoutine;
	int mReadMemoryRoutine;
	int mWriteMemoryRoutine;
	int mProtectMemoryRoutine;
	int mAddressTableUpdateInterval;
	
	int mStackSnapshotLimit;
	bool mAttemptHideDebuggerPeb;
	bool mInvadeProcess;
	Vector<String> mSymbolPaths;
	
	bool mEnableHotkeys;
	Vector<CrySearchHotKey> hotkeys;
public:
	SettingsFile();
	
	// inline getters for settings variables
	const bool GetFastScanByDefault() const						{ return this->mFastScanByDefault; }
	
	const bool GetScanWritableMemory() const					{ return this->mScanWritableMemory; }
	const bool GetScanExecutableMemory() const					{ return this->mScanExecutableMemory; }
	const bool GetScanCopyOnWriteMemory() const					{ return this->mScanCopyOnWriteMemory; }
	
	const bool GetScanMemPrivate() const						{ return this->mScanMemPrivate; }
	const bool GetScanMemImage() const							{ return this->mScanMemImage; }
	const bool GetScanMemMapped() const							{ return this->mScanMemMapped; }
	
	const int GetScanThreadPriority() const						{ return this->mScanningThreadPriority; }
	
	const int GetOpenProcessRoutine() const						{ return this->mOpenProcessRoutine; }
	const int GetReadMemoryRoutine() const						{ return this->mReadMemoryRoutine; }
	const int GetWriteMemoryRoutine() const						{ return this->mWriteMemoryRoutine; }
	const int GetProtectMemoryRoutine() const					{ return this->mProtectMemoryRoutine; }
	
	const int GetStackSnapshotLimit() const						{ return this->mStackSnapshotLimit; }
	const int GetAddressTableUpdateInterval() const				{ return this->mAddressTableUpdateInterval; }
	const bool GetAttemptHideDebuggerFromPeb() const			{ return this->mAttemptHideDebuggerPeb; }
	
	const bool GetEnableHotkeys() const							{ return this->mEnableHotkeys; }
	const bool GetInvadeProcess() const							{ return this->mInvadeProcess; }
	
	// inline setters for settings variables
	void SetFastScanByDefault(bool value = true)				{ this->mFastScanByDefault = value; }	
	
	void SetScanWritableMemory(bool value = true)				{ this->mScanWritableMemory = value; }
	void SetScanExecutableMemory(bool value = true)				{ this->mScanExecutableMemory = value; }
	void SetScanCopyOnWriteMemory(bool value = true)			{ this->mScanCopyOnWriteMemory = value; }
	
	void SetScanMemPrivate(bool value = true)					{ this->mScanMemPrivate = value; }
	void SetScanMemImage(bool value = true)						{ this->mScanMemImage = value; }
	void SetScanMemMapped(bool value = true)					{ this->mScanMemMapped = value; }
	
	void SetScanThreadPriority(int value = 2)					{ this->mScanningThreadPriority = value; }
	
	void SetOpenProcessRoutine(int value = 0)					{ this->mOpenProcessRoutine = value; }
	void SetReadMemoryRoutine(int value = 0)					{ this->mReadMemoryRoutine = value; }
	void SetWriteMemoryRoutine(int value = 0)					{ this->mWriteMemoryRoutine = value; }
	void SetProtectMemoryRoutine(int value = 0)					{ this->mProtectMemoryRoutine = value; }
	
	void SetAddressTableUpdateInterval(int value = 500)			{ this->mAddressTableUpdateInterval = value; }
	void SetAttemptHideDebuggerFromPeb(bool value = true)		{ this->mAttemptHideDebuggerPeb = value; }
	
	void SetStackSnapshotLimit(int value = 1024)				{ this->mStackSnapshotLimit = value; }
	
	void SetEnableHotkeys(bool value = true)					{ this->mEnableHotkeys = value; }
	void SetInvadeProcess(bool value = true)					{ this->mInvadeProcess = value; }
	
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
};

#endif
