#include "SettingsFile.h"

// Checks whether the settings configuration file exists.
const bool SettingsFile::ConfigFileExists()
{
	return FileExists(ConfigFile(SettingsFile::GetInstance()->GetSettingsFilename()));
};

// Procedure that converts settings to XML and back.
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
		("ViewOffsetsInHexadecimal", this->mViewOffsetsInHexadecimal)
		("EnableReadOnlyMode", this->mEnableReadOnlyMode)
		("LeaveUnbackedPagesAlone", this->mLeaveUnbackedPagesAlone)
		("OpenProcessRoutine", this->mOpenProcessRoutine)
		("ReadMemoryRoutine", this->mReadMemoryRoutine)
		("WriteMemoryRoutine", this->mWriteMemoryRoutine)
		("ProtectMemoryRoutine", this->mProtectMemoryRoutine)
		("AddressTableUpdateInterval", this->mAddressTableUpdateInterval)
		("LibraryInjectionMethod", this->mLibraryInjectionMethod)
		("StackSnapshotLimit", this->mStackSnapshotLimit)
		("AttemptHideDebuggerFromPeb", this->mAttemptHideDebuggerPeb)
		("CatchAllExceptions", this->mCatchAllExceptions)
		("InvadeProcess", this->mInvadeProcess)
		("SymbolPaths", this->mSymbolPaths)
		("EnableHotkeys", this->mEnableHotkeys)
		("HotkeyList", this->hotkeys)
		("DissectionUpdateInterval", this->mDissectionUpdateInterval)
		("DissectionHexView", this->mDissectionHexView)
		("DissectionEnableTypeGuessing", this->mEnableDissectionTypeGuessing)
		("HideNonWow64Modules", this->mHideNonWow64Modules)
		("SignatureMaskingByDefault", this->mSignatureMaskingByDefault)
		("WarnForPackedProcess", this->mWarnForPackedProcess)
		("ShowArchitectureInProcWindow", this->mShowArchitectureInProcWindow)
		("ResolveDisassemblyImportedFunctions", this->mResolveDisassemblyImportedFunctions)
	;
}

// Default settings file constructor.
SettingsFile::SettingsFile()
{
	this->obfuscation[0] = 0x53797243;
	this->obfuscation[1] = 0x63726165;
	this->obfuscation[2] = 0x6d782e68;
	this->obfuscation[3] = 0x6c;
}

// Default settings file destructor.
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
	this->SetEnableReadOnlyMode();
	this->SetLeaveUnbackedPagesAlone();
	this->SetOpenProcessRoutine();
	this->SetViewOffsetsInHexadecimal();
	this->SetReadMemoryRoutine();
	this->SetWriteMemoryRoutine();
	this->SetProtectMemoryRoutine();
	this->SetLibraryInjectionMethod();
	this->SetAddressTableUpdateInterval();
	this->SetStackSnapshotLimit();
	this->SetCatchAllExceptions();
	this->SetDissectionUpdateInterval();
	this->SetDissectionHexadecimalView();
	this->SetEnableDissectionTypeGuessing();
	this->SetHideNonWow64Modules();
	this->SetSignatureMaskingByDefault();
	this->SetWarnForPackedProcess();
	this->SetShowArchitectureInProcWindow();
	this->SetResolveDisasmImportedFunctions();
	this->Save();
}

// Loads settings data from file and stores it in memory.
bool SettingsFile::Initialize()
{
	bool b;
	char binDir[MAX_PATH];
	if (GetModuleFileName(NULL, binDir, MAX_PATH))
	{
		b = LoadFromXMLFile(*this, GetFileDirectory(binDir) + (char*)this->obfuscation);
	}
	else
	{
		b = LoadFromXMLFile(*this, (char*)this->obfuscation);
	}
	
	this->mLanguage = LNGFromText("EN-EN");
	
	return b;
}

// Saves the data currently in memory to XML.
void SettingsFile::Save()
{
	char binDir[MAX_PATH];
	if (GetModuleFileName(NULL, binDir, MAX_PATH))
	{
		StoreAsXMLFile(*this, "ApplicationSettings", GetFileDirectory(binDir) + (char*)this->obfuscation);
	}
	else
	{
		StoreAsXMLFile(*this, "ApplicationSettings", (char*)this->obfuscation);
	}
}

// Adds a hotkey to the settings file object.
void SettingsFile::AddHotkey(const String& description, unsigned int key)
{
	CrySearchHotKey _key;
	_key.Key = key;
	_key.Description = description;
	this->hotkeys.Add(_key);
}

// Deletes a hotkey from the settings file object.
void SettingsFile::DeleteHotKey(const unsigned int index)
{
	this->hotkeys.Remove(index);
}

// Retrieves a hotkey information structure from the settings file object.
CrySearchHotKey& SettingsFile::GetHotkey(const unsigned int index)
{
	return this->hotkeys[index];
}

// Adds a symbol path to the list of paths. Returns true if path did not yet exist and false if it did exist. If it existed, nothing is added.
bool SettingsFile::AddSymbolPath(const String& path)
{
	for (auto const& sp : this->mSymbolPaths)
	{
		if (sp == path)
		{
			return false;
		}
	}
	
	this->mSymbolPaths.Add(path);
	return true;
}

// Deletes a symbol path from the settings file object.
void SettingsFile::DeleteSymbolPath(const int index)
{
	this->mSymbolPaths.Remove(index);
}