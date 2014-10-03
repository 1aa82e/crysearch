#include "SettingsFile.h"

// Checks whether the settings configuration file exists.
bool ConfigFileExists()
{
	return FileExists(ConfigFile("CrySearch.xml"));
};

void SettingsFile::Xmlize(XmlIO& pXml)
{
	pXml
		("FastScanByDefault", this->mFastScanByDefault)
		("ScanWritableMemory", this->mScanWritableMemory)
		("ScanExecutableMemory", this->mScanExecutableMemory)
		("ScanCopyOnWriteMemory", this->mScanCopyOnWriteMemory)
		("ScanMemPrivate", this->mScanMemPrivate)
		("ScanMemImage", this->mScanMemImage)
		("ScanMemMapped", this->mScanMemMapped)
		("ScanningThreadPriority", this->mScanningThreadPriority)
		("OpenProcessRoutine", this->mOpenProcessRoutine)
		("ReadMemoryRoutine", this->mReadMemoryRoutine)
		("WriteMemoryRoutine", this->mWriteMemoryRoutine)
		("ProtectMemoryRoutine", this->mProtectMemoryRoutine)
		("AddressTableUpdateInterval", this->mAddressTableUpdateInterval)
		("StackSnapshotLimit", this->mStackSnapshotLimit)
		("AttemptHideDebuggerFromPeb", this->mAttemptHideDebuggerPeb)
		("CatchAllExceptions", this->mCatchAllExceptions)
		("InvadeProcess", this->mInvadeProcess)
		("SymbolPaths", this->mSymbolPaths)
		("EnableHotkeys", this->mEnableHotkeys)
		("HotkeyList", this->hotkeys)
		("DissectionUpdateInterval", this->mDissectionUpdateInterval)
		("DissectionHexView", this->mDissectionHexView)
	;
}

SettingsFile::SettingsFile()
{
	
}

SettingsFile::~SettingsFile()
{
	
}

// (Re)-loads the default settings for a CrySearch distribution.
void SettingsFile::DefaultSettings()
{
	this->SetFastScanByDefault();
	this->SetScanWritableMemory();
	this->SetScanExecutableMemory();
	this->SetScanMemImage();
	this->SetScanMemPrivate();
	this->SetScanMemImage();
	this->SetScanThreadPriority();
	this->SetOpenProcessRoutine();
	this->SetReadMemoryRoutine();
	this->SetWriteMemoryRoutine();
	this->SetProtectMemoryRoutine();
	this->SetAddressTableUpdateInterval();
	this->SetStackSnapshotLimit();
	this->SetCatchAllExceptions();
	this->SetDissectionUpdateInterval();
	this->SetDissectionHexadecimalView();
	this->Save();
}

// Loads settings data from file and stores it in memory.
bool SettingsFile::Initialize()
{
	bool b;
	char binDir[MAX_PATH];
	if (GetModuleFileName(NULL, binDir, MAX_PATH))
	{
		b = LoadFromXMLFile(*this, GetFileDirectory(binDir) + "CrySearch.xml");
	}
	else
	{
		b = LoadFromXMLFile(*this, "CrySearch.xml");
	}
	
	this->mLanguage = LNGFromText("EN-EN");
	
	// If a simple integer value in the settings file is bogus, the file is corrupt.
	if (this->mOpenProcessRoutine > 1)
	{
		b = false;
	}
	
	return b;
}

// Saves the data currently in memory to XML.
void SettingsFile::Save()
{
	char binDir[MAX_PATH];
	if (GetModuleFileName(NULL, binDir, MAX_PATH))
	{
		StoreAsXMLFile(*this, "ApplicationSettings", GetFileDirectory(binDir) + "CrySearch.xml");
	}
	else
	{
		StoreAsXMLFile(*this, "ApplicationSettings", "CrySearch.xml");
	}
}

void SettingsFile::AddHotkey(const String& description, unsigned int key)
{
	CrySearchHotKey _key;
	_key.Key = key;
	_key.Description = description;
	this->hotkeys.Add(_key);
}

void SettingsFile::DeleteHotKey(const unsigned int index)
{
	this->hotkeys.Remove(index);
}

CrySearchHotKey& SettingsFile::GetHotkey(const unsigned int index)
{
	return this->hotkeys[index];
}

// Adds a symbol path to the list of paths. Returns true if path did not yet exist and false if it did exist. If it existed, nothing is added.
bool SettingsFile::AddSymbolPath(const String& path)
{
	for (int i = 0; i < this->mSymbolPaths.GetCount(); i++)
	{
		if (this->mSymbolPaths[i] == path)
		{
			return false;
		}
	}
	
	this->mSymbolPaths.Add(path);
	return true;
}

void SettingsFile::DeleteSymbolPath(const int index)
{
	this->mSymbolPaths.Remove(index);
}