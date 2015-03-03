// Nessecary dialog includes and IML provider for imaging.
#include "CrySearchForm.h"
#include "CrySettingsDialog.h"
#include "CrySearchAboutDialog.h"
#include "CryProcessEnumeratorForm.h"
#include "CryNewScanForm.h"
#include "CryAllocateMemoryWindow.h"
#include "CryCodeGenerationForm.h"
#include "CryMemoryDissectionWindow.h"
#include "CryProcessEnvironmentBlockWindow.h"
#include "CrySystemHandleInformationWindow.h"
#include "CryPluginsWindow.h"
#include "CrashHandler.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// Global source IML file declaration. Imaging in the GUI depends on this.
#define IMAGECLASS CrySearchIml
#define IMAGEFILE "CrySearch.iml"
#include <Draw/iml_source.h>

// ---------------------------------------------------------------------------------------------

// Global declaration of the memory scanner class instance which technically runs the application.
MemoryScanner* mMemoryScanner;

// Global declaration of the plugin system class.
PluginSystem* mPluginSystem;

// Address table instance that provides the user access to address tables.
AddressTable loadedTable;
bool viewAddressTableValueHex = false;

// Global declaration of the module manager class.
ModuleManager* mModuleManager;

// Global PE methodic class instance, nessecary for over half of the application.
PortableExecutable* mPeInstance;

// Global Debugger class instance, necessary for debugging the remote process.
CryDebugger* mDebugger;

// Stored process PE information.
Win32PEInformation LoadedProcessPEInformation;

// ---------------------------------------------------------------------------------------------

// Subwindows or controls that are managed by the main window class may be needed outside. A globally defined pointer is necessary.
CrySearchWindowManager* mCrySearchWindowManager;

// ---------------------------------------------------------------------------------------------

String GetAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(CachedAddresses[index].Address);
#else
	return FormatIntHexUpper(CachedAddresses[index].Address, 0);
#endif
}

// Virtual array control row accessors.
String GetValue(const int index)
{
	if (!mMemoryScanner->IsScanRunning())
	{
		const bool mustHex = GlobalScanParameter->CurrentScanHexValues;
		if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_BYTE)
		{
			Byte value;
			if (mMemoryScanner->Peek<Byte>(CachedAddresses[index].Address, 0, &value))
			{
				return mustHex ? FormatIntHexUpper(value) : IntStr(value);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_2BYTE)
		{
			short value;
			if (mMemoryScanner->Peek<short>(CachedAddresses[index].Address, 0, &value))
			{
				return mustHex ? FormatIntHexUpper(value) : IntStr(value);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_4BYTE)
		{
			int value;
			if (mMemoryScanner->Peek<int>(CachedAddresses[index].Address, 0, &value))
			{
				return mustHex ? FormatIntHexUpper(value) : IntStr(value);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_8BYTE)
		{
			__int64 value;
			if (mMemoryScanner->Peek<__int64>(CachedAddresses[index].Address, 0, &value))
			{
				return mustHex ? FormatInt64HexUpper(value) : IntStr64(value);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_FLOAT)
		{
			float value;
			if (mMemoryScanner->Peek<float>(CachedAddresses[index].Address, 0, &value))
			{
				return DblStr(value);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_DOUBLE)
		{
			double value;
			if (mMemoryScanner->Peek<double>(CachedAddresses[index].Address, 0, &value))
			{
				return DblStr(value);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_AOB)
		{
			ArrayOfBytes value;
			if (mMemoryScanner->Peek<ArrayOfBytes>(CachedAddresses[index].Address, GlobalScanParameter->ValueSize, &value))
			{
				return BytesToString(value.Data, GlobalScanParameter->ValueSize);
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_STRING)
		{
			String value;
			if (mMemoryScanner->Peek<String>(CachedAddresses[index].Address, GlobalScanParameter->ValueSize, &value))
			{
				return value;
			}
		}
		else if (GlobalScanParameter->GlobalScanValueType == VALUETYPE_WSTRING)
		{
			WString value;
			if (mMemoryScanner->Peek<WString>(CachedAddresses[index].Address, GlobalScanParameter->ValueSize, &value))
			{
				return value.ToString();
			}
		}
	}

	return "???";
}

String GetAddressTableDescription(const int index)
{
	return loadedTable[index]->Description;
}

String GetAddressTableAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(loadedTable[index]->Address);
#else
	return FormatIntHexUpper(loadedTable[index]->Address, 0);
#endif
}

String GetAddressTableValue(const int index)
{
	if (mMemoryScanner->GetProcessId())
	{
		const AddressTableEntry* const entry = loadedTable[index];
		if (entry->ValueType == CRYDATATYPE_BYTE)
		{
			Byte value;
			if (mMemoryScanner->Peek<Byte>(entry->Address, 0, &value))
			{
				return viewAddressTableValueHex ? FormatIntHexUpper(value) : IntStr(value);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_2BYTES)
		{
			short value;
			if (mMemoryScanner->Peek<short>(entry->Address, 0, &value))
			{
				return viewAddressTableValueHex ? FormatIntHexUpper(value) : IntStr(value);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_4BYTES)
		{
			int value;
			if (mMemoryScanner->Peek<int>(entry->Address, 0, &value))
			{
				return viewAddressTableValueHex ? FormatIntHexUpper(value) : IntStr(value);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_8BYTES)
		{
			__int64 value;
			if (mMemoryScanner->Peek<__int64>(entry->Address, 0, &value))
			{
				return viewAddressTableValueHex ? FormatInt64HexUpper(value) : IntStr64(value);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_FLOAT)
		{
			float value;
			if (mMemoryScanner->Peek<float>(entry->Address, 0, &value))
			{
				return DblStr(value);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_DOUBLE)
		{
			double value;
			if (mMemoryScanner->Peek<double>(entry->Address, 0, &value))
			{
				return DblStr(value);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_AOB)
		{
			ArrayOfBytes value;
			if (mMemoryScanner->Peek<ArrayOfBytes>(entry->Address, entry->Size, &value))
			{
				return BytesToString(value.Data, value.Size);
			}
		}
		else if (entry->ValueType == CRYDATATYPE_STRING)
		{
			String value;
			if (mMemoryScanner->Peek<String>(entry->Address, entry->Size, &value))
			{
				return value;
			}
		}
		else if (entry->ValueType == CRYDATATYPE_WSTRING)
		{
			WString value;
			if (mMemoryScanner->Peek<WString>(entry->Address, entry->Size, &value))
			{
				return value.ToString();
			}
		}		
	}
	
	return "???";
}

String GetAddressTableValueType(const int index)
{
	return GetCrySearchDataTypeRepresentation(loadedTable[index]->ValueType);
}

// ---------------------------------------------------------------------------------------------

// Checks key presses across all controls. Consider it a global key event function.
void CrySearchForm::CheckKeyPresses()
{
	if (SettingsFile::GetInstance()->GetEnableHotkeys())
	{
		const unsigned int count = SettingsFile::GetInstance()->GetHotkeyCount();
		if (count > 0)
		{
			// Iterate saved hotkeys and configure parameters for its configured actions.
			for (unsigned int i = 0; i < count; ++i)
			{
				const CrySearchHotKey& curKey = SettingsFile::GetInstance()->GetHotkey(i);
				
				// Check if the configured key is currently pressed.
				if (GetAsyncKeyState(curKey.Key) & 1)
				{
					if (!mMemoryScanner->IsScanRunning() && mMemoryScanner->GetScanResultCount() > 0)
					{
						if (curKey.Description == "Refresh search results, changed value")
						{
							GlobalScanParameter->GlobalScanType = SCANTYPE_CHANGED;
						}
						else if (curKey.Description == "Refresh search results, unchanged value")
						{
							GlobalScanParameter->GlobalScanType = SCANTYPE_UNCHANGED;
						}
						else if (curKey.Description == "Refresh search results, increased value")
						{
							GlobalScanParameter->GlobalScanType = SCANTYPE_INCREASED;
						}
						else if (curKey.Description == "Refresh search results, decreased value")
						{
							GlobalScanParameter->GlobalScanType = SCANTYPE_DECREASED;
						}
						
						// Finally, execute the action for all of these. (Since its the same for all)
						curKey.Action();
					}
				}
			}
		}
	}
	
	// Reinstate the callback for the next iteration.
	SetTimeCallback(100, THISBACK(CheckKeyPresses), 20);
}

// ---------------------------------------------------------------------------------------------

void CrySearchForm::SearchResultListUpdater()
{
	// Refresh the address table ArrayCtrl to force updating of the values.
	this->mScanResults.Refresh();
	
	// Reinstate the callback for the next iteration.
	SetTimeCallback(1000, THISBACK(SearchResultListUpdater), 21);
}

void CrySearchForm::AddressValuesUpdater()
{
	// Handle frozen addresses
	const int addrTableCount = loadedTable.GetCount();
	for (int i = 0; i < addrTableCount; ++i)
	{
		const AddressTableEntry* curEntry = loadedTable[i];
		if (curEntry->Frozen)
		{
			if (curEntry->ValueType == CRYDATATYPE_BYTE)
			{
				mMemoryScanner->Poke<Byte>(curEntry->Address, (Byte)ScanInt(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == CRYDATATYPE_2BYTES)
			{
				mMemoryScanner->Poke<short>(curEntry->Address, (short)ScanInt(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == CRYDATATYPE_4BYTES)
			{
				mMemoryScanner->Poke<int>(curEntry->Address, ScanInt(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == CRYDATATYPE_8BYTES)
			{
				mMemoryScanner->Poke<__int64>(curEntry->Address, ScanInt64(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == CRYDATATYPE_FLOAT)
			{
				mMemoryScanner->Poke<float>(curEntry->Address, (float)StrDbl(curEntry->Value));
			}
			else if (curEntry->ValueType == CRYDATATYPE_DOUBLE)
			{
				mMemoryScanner->Poke<double>(curEntry->Address, StrDbl(curEntry->Value));
			}
			else if (curEntry->ValueType == CRYDATATYPE_AOB)
			{
				ArrayOfBytes aob = StringToBytes(curEntry->Value);
				mMemoryScanner->Poke(curEntry->Address, aob);
				curEntry->Size = aob.Size;
			}
			else if (curEntry->ValueType == CRYDATATYPE_STRING)
			{
				mMemoryScanner->Poke<String>(curEntry->Address, curEntry->Value);
			}
			else if (curEntry->ValueType == CRYDATATYPE_WSTRING)
			{
				mMemoryScanner->Poke<WString>(curEntry->Address, curEntry->Value.ToWString());
			}
		}
	}
	
	// Refresh the address table ArrayCtrl to force the values to update.
	this->mUserAddressList.Refresh();
	
	// Reinstate timer queue callback to ensure timer keeps running.
	SetTimeCallback(SettingsFile::GetInstance()->GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
}

// This callback checks whether the process is still running, if one is opened.
// If the opened process terminated somehow, CrySearch will close it internally.
void CrySearchForm::CheckProcessTermination()
{
	if (mMemoryScanner->GetProcessId() > 0)
	{
		if (!IsProcessActive(mMemoryScanner->GetHandle()))
		{
			this->ProcessTerminated = true;
			this->ScannerErrorOccured(PROCESSWASTERMINATED);
			
			// Kill the callback, otherwise errors will keep coming.
			KillTimeCallback(30);
		}
	}
	
	SetTimeCallback(250, THISBACK(CheckProcessTermination), 30);
}

// Link hotkeys to the correct callbacks according to the settings file.
void CrySearchForm::LinkHotkeysToActions()
{
	SettingsFile* const settings = SettingsFile::GetInstance();
	for (unsigned int i = 0; i < settings->GetHotkeyCount(); i++)
	{
		settings->GetHotkey(i).Action = THISBACK(StartNextScanHotkey);
	}
}

// ---------------------------------------------------------------------------------------------

// If CrySearch was opened using a file association, open the file straight away.
// If CrySearch was opened regularly, pass NULL as parameter.
CrySearchForm::CrySearchForm(const char* fn)
{
	this->processLoaded = false;
	this->wndTitleRandomized = false;
	this->lowerPaneHidden = false;
	this->mWindowManager.SetParentWindow(this);
	
	DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
	this->Title((char*)wndTitle).Icon(CrySearchIml::CrySearch()).Sizeable().Zoomable().SetRect(0, 0, 800, 600);
	this->SetMinSize(Size(640, 480));
	
	this->AddFrame(mMenuStrip);
	this->mMenuStrip.Set(THISBACK(MainMenu));
	
	this->AddFrame(mToolStrip);
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	this->mScanResults.CryAddRowNumColumn("Address").SetConvert(Single<IndexBasedValueConvert<GetAddress>>());
	this->mScanResults.CryAddRowNumColumn("Value").SetConvert(Single<IndexBasedValueConvert<GetValue>>());
	this->mScanResults.WhenLeftDouble = THISBACK(SearchResultDoubleClicked);
	this->mScanResults.WhenBar = THISBACK(SearchResultWhenBar);
	
	this->mUserAddressList.CryAddRowNumColumn("Description").SetConvert(Single<IndexBasedValueConvert<GetAddressTableDescription>>());
	this->mUserAddressList.CryAddRowNumColumn("Address").SetConvert(Single<IndexBasedValueConvert<GetAddressTableAddress>>());
	this->mUserAddressList.CryAddRowNumColumn("Value").SetConvert(Single<IndexBasedValueConvert<GetAddressTableValue>>());
	this->mUserAddressList.CryAddRowNumColumn("Type").SetConvert(Single<IndexBasedValueConvert<GetAddressTableValueType>>());
	this->mUserAddressList.WhenBar = THISBACK(UserDefinedEntryWhenBar);
	this->mUserAddressList.WhenLeftDouble = THISBACK(UserDefinedEntryWhenDoubleClicked);

	this->mSearchResultsPanel
		<< this->mSearchResultCount.SetLabel("Search Results: 0").HSizePosZ(5, 5).TopPos(5, 20)
		<< this->mScanningProgress.RightPos(5, 120).TopPos(5, 20)
		<< this->mScanResults.MultiSelect(false).HSizePosZ(5, 5).VSizePosZ(30, 0)
	;
	
	this->mUserAddressPanel << this->mUserAddressList.HSizePos(5, 5).VSizePos(5);
	
	this->mScanningProgress.Hide();
	this->mTabbedDataWindows.WhenSet = THISBACK(ActiveTabWindowChanged);
	
	*this
		<< this->mMainSplitter.Vert(this->mInputScanSplitter.Horz(this->mSearchResultsPanel, this->mUserAddressPanel)
			, this->mTabbedDataWindows.SizePos())
	;
	
	this->SetMainSplitterPosition();
	this->mMainSplitter.SetMinPixels(0, 100);
	this->mMainSplitter.SetMinPixels(1, 100);
	this->mInputScanSplitter.SetMinPixels(0, 300);
	this->mInputScanSplitter.SetMinPixels(1, 250);
	
	// If settings configuration file is not found, create a new one using default settings.
	if (!ConfigFileExists() || !SettingsFile::GetInstance()->Initialize())
	{
		//Prompt("Settings Error", CtrlImg::exclamation(), "The settings file was not found or corrupt, and has been overwritten with the defaults. If this is your first run, you can ignore this warning.", "OK");
		SettingsFile::GetInstance()->DefaultSettings();
	}
	
	// The settings file saves some routines too. Set the correct routines.
	CrySearchRoutines.InitializeRoutines();
	
	// If one of more NTDLL functions were not succesfully retrieved, notify the user about it.
	if (CrySearchRoutines.ErrorOccured())
	{
		Prompt("Behavioral Warning", CtrlImg::exclamation(), "One or more NTDLL functions were not retrieved succesfully. CrySearch may behave unpredictable from here.", "OK");
	}
	
	// Initiate the memory scanner class, the most important part of CrySearch.
	mMemoryScanner = MemoryScanner::GetInstance();
	mMemoryScanner->ErrorOccured = THISBACK(ScannerErrorOccured);
	mMemoryScanner->ScanCompleted = THISBACK(ScannerCompletedScan);
	mMemoryScanner->UpdateScanningProgress = THISBACK(ScannerUserInterfaceUpdate);
	mMemoryScanner->ScanStarted = THISBACK(ScannerScanStarted);
	
	// Make sure the module manager is initialized.
	mModuleManager = ModuleManager::GetInstance();
	
	// Initialize the plugin system.
	mPluginSystem = PluginSystem::GetInstance();
	mPluginSystem->RetrieveAndLoadAllPlugins();
	
	// Set timer that runs keeping track of hotkeys.
	SetTimeCallback(100, THISBACK(CheckKeyPresses), 20);

	// Set timer callback that runs the address list update sequence.
	SetTimeCallback(SettingsFile::GetInstance()->GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
	
	// Set timer callback that runs the search results update sequence.
	SetTimeCallback(1000, THISBACK(SearchResultListUpdater), 21);
	
	// Assign proper callback functions to configured hotkeys.
	this->LinkHotkeysToActions();
	
	// Wind up UI debugger error event. When attaching fails, the debug window must be closed at once.
	this->mWindowManager.GetDebuggerWindow()->DebugErrorOccured = THISBACK(DebugWindowErrorOccured);
	
	// If an address table file was opened using file association, load it and display it.
	if (fn)
	{
		AddressTable::CreateAddressTableFromFile(loadedTable, fn);
		this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	}
}

CrySearchForm::~CrySearchForm()
{
	// Stop the timer callbacks that are running.
	KillTimeCallback(10);
	KillTimeCallback(20);
	KillTimeCallback(30);
}

void CrySearchForm::MainMenu(Bar& pBar)
{
	pBar.Add("File", THISBACK(FileMenu));
	pBar.Add("Edit", THISBACK(EditMenu));
	pBar.Add("Tools", THISBACK(ToolsMenu));
	
	if (this->processLoaded)
	{
		pBar.Add("Debugger", THISBACK(DebuggerMenu));
	}
	
	pBar.Add("Window", THISBACK(WindowMenu));
	pBar.Add("Help", THISBACK(HelpMenu));
	
	// When the window title is randomized the opened process should be listed in the label below the bar.
	pBar.MenuGapRight();
	pBar.Add(this->mOpenedProcess.SetAlign(ALIGN_RIGHT), 200);
}

void CrySearchForm::ToolStrip(Bar& pBar)
{
	pBar.Add("Open Process", CrySearchIml::AttachToProcessMenu(), THISBACK(OpenProcessMenu));
	pBar.Add(this->processLoaded && !mMemoryScanner->IsScanRunning(), "Search", CrySearchIml::SearchMemoryMenu(), THISBACK(MemorySearch));
	pBar.Add(this->processLoaded && !mMemoryScanner->IsScanRunning() && mScanResults.GetCount() > 0, "Refresh search results", CrySearchIml::NextScanMenu(), THISBACK(RefreshSearchResults));
}

void CrySearchForm::FileMenu(Bar& pBar)
{
	pBar.Add("Open Process", CrySearchIml::AttachToProcessMenu(), THISBACK(OpenProcessMenu));
	pBar.Add(this->processLoaded, "Close Process", THISBACK(CloseProcessMenu));
	pBar.Separator();
	
	pBar.Add("Open File", CrySearchIml::OpenFile(), THISBACK(OpenFileMenu));
	
	if (loadedTable.GetFileName().IsEmpty())
	{
		pBar.Add(false, "Save File", CrySearchIml::SaveFile(), THISBACK(SaveFileMenu));
	}
	else
	{
		pBar.Add(true, "Save File", CrySearchIml::SaveFile(), THISBACK(SaveFileMenu));
	}
	
	pBar.Add("Save File As", THISBACK(SaveFileAsMenu));
	
	pBar.Separator();
	pBar.Add("Exit", CrySearchIml::ExitApplication(), THISBACK(ExitApplication));
}

void CrySearchForm::EditMenu(Bar& pBar)
{
	pBar.Add((this->mScanResults.GetCount() > 0), "Clear Scan Results", THISBACK(ClearScanResultsWithoutWarning));
	pBar.Add((this->mUserAddressList.GetCount() > 0), "Clear Address List", THISBACK(ClearAddressList));
	
	pBar.Separator();
	pBar.Add("Settings", CrySearchIml::SettingsButton(), THISBACK(SettingsButtonClicked));
}

void CrySearchForm::ToolsMenu(Bar& pBar)
{
	if (this->processLoaded)
	{
		pBar.Add("View PEB", CrySearchIml::AboutButton(), THISBACK(ViewPEBButtonClicked));
		pBar.Add("View Handles", CrySearchIml::ViewHandlesButton(), THISBACK(ViewSystemHandlesButtonClicked));
		pBar.Separator();
		pBar.Add("Allocate Memory", CrySearchIml::AllocateMemoryButton(), THISBACK(AllocateMemoryButtonClicked));
		pBar.Add("Memory Dissection", CrySearchIml::MemoryDissection(), THISBACK(MemoryDissectionButtonClicked));
		pBar.Separator();
		pBar.Add((this->mUserAddressList.GetCount() > 0), "Code Generation", CrySearchIml::CodeGenerationButton(), THISBACK(CodeGenerationButtonClicked));
		pBar.Separator();
	}
	
	pBar.Add("Plugins", CrySearchIml::PluginsMenuSmall(), THISBACK(PluginsMenuClicked));
}

void CrySearchForm::DebuggerMenu(Bar& pBar)
{
	if (this->processLoaded)
	{
		const bool isAttached = mDebugger->IsDebuggerAttached();
		
		pBar.Add(!isAttached, "Attach", CrySearchIml::DebuggerAttach(), THISBACK(DebuggerAttachMenu));
		pBar.Add(isAttached, "Detach", THISBACK(DebuggerDetachMenu));
	}
}

void CrySearchForm::WindowMenu(Bar& pBar)
{
	pBar.Add("Always on top", THISBACK(ToggleAlwaysOnTop)).Check(this->IsTopMost());
	pBar.Add("Randomize window title", THISBACK(RandomizeWindowTitle)).Check(this->wndTitleRandomized);
	pBar.Add("Hide lower pane", THISBACK(HideLowerPaneButtonClicked)).Check(this->lowerPaneHidden);
	
	if (this->processLoaded)
	{
		pBar.Separator();
		pBar.Add("General", CrySearchIml::ViewGeneralButton(), THISBACK(ViewGeneralButtonClicked)).Check(IsTabPageOpened(this->mTabbedDataWindows, "General") >= 0);
		pBar.Add("Disassembly", CrySearchIml::DisassemblyIcon(), THISBACK(ShowHideDisasmWindow)).Check(IsTabPageOpened(this->mTabbedDataWindows, "Disassembly") >= 0);
		pBar.Add("Imports", CrySearchIml::ViewImportsButton(), THISBACK(ViewImportsButtonClicked)).Check(IsTabPageOpened(this->mTabbedDataWindows, "Imports") >= 0);
		pBar.Add("Threads", CrySearchIml::ViewThreadsButton(), THISBACK(ViewThreadsButtonClicked)).Check(IsTabPageOpened(this->mTabbedDataWindows, "Threads") >= 0);
		pBar.Add("Modules", CrySearchIml::ViewModulesButton(), THISBACK(ViewModulesButtonClicked)).Check(IsTabPageOpened(this->mTabbedDataWindows, "Modules") >= 0);
	}
}

void CrySearchForm::HelpMenu(Bar& pBar)
{
	pBar.Add("About", CrySearchIml::AboutButton(), THISBACK(AboutCrySearch));
}

void CrySearchForm::HideLowerPaneButtonClicked()
{
	Rect r = this->GetRect();
	if (this->lowerPaneHidden)
	{
		this->mMainSplitter.Add(this->mTabbedDataWindows.SizePos());
		this->SetMinSize(Size(640, 480));
		r.bottom += 220;
		this->SetRect(r);
		this->SetMainSplitterPosition();
	}
	else
	{
		this->mMainSplitter.Remove(this->mTabbedDataWindows);
		this->SetMinSize(Size(640, 220));
		const int remaining = r.bottom - r.top;
		r.bottom = remaining < 220 ? r.bottom - remaining : 220;
		this->SetRect(r);
		this->SetMainSplitterPosition();
	}
	
	this->lowerPaneHidden = !this->lowerPaneHidden;
}

void CrySearchForm::SetMainSplitterPosition()
{
	const Rect r = this->mMainSplitter.GetRect();
	const int total = r.bottom - r.top;
	this->mMainSplitter.SetPos(((total / 2) * 10000 / total) - 600);
}

void CrySearchForm::ChangeRecordSubMenu(Bar& pBar)
{
	pBar.Add("Description", THISBACK1(AddressListChangeProperty, CRDM_DESCRIPTION));
	pBar.Add("Address", THISBACK1(AddressListChangeProperty, CRDM_ADDRESS));
	pBar.Add("Value", THISBACK1(AddressListChangeProperty, CRDM_VALUE));
	pBar.Add("Type", THISBACK1(AddressListChangeProperty, CRDM_TYPE));
}

void CrySearchForm::UserDefinedEntryWhenBar(Bar& pBar)
{
	pBar.Add("Manually add address", CrySearchIml::AddToAddressList(), THISBACK(ManuallyAddAddressToTable));
	
	const int row = this->mUserAddressList.GetCursor();
	if (row >= 0 && loadedTable.GetCount() > 0)
	{
		pBar.Add("Dissect memory", CrySearchIml::MemoryDissection(), THISBACK(AddressListEntryMemoryDissection));
		pBar.Separator();
		
		if (loadedTable[row]->Frozen)
		{
			pBar.Add("Thaw", CrySearchIml::ThawIconSmall(), THISBACK(ToggleAddressTableFreezeThaw));
		}
		else
		{
			pBar.Add("Freeze", CrySearchIml::FreezeAddressSmall(), THISBACK(ToggleAddressTableFreezeThaw));
		}
		
		// Add decimal/hexadecimal toggle button.
		pBar.Add(viewAddressTableValueHex ? "View as decimal" : "View as hexadecimal", THISBACK(ToggleAddressTableValueView)).Check(viewAddressTableValueHex);
		
		const bool canDbg = (mDebugger && mDebugger->IsDebuggerAttached());
		if (mDebugger && mDebugger->FindBreakpoint(loadedTable[row]->Address) == -1)
		{
			pBar.Add(canDbg, "Set Breakpoint", CrySearchIml::SetBreakpoint(), THISBACK(SetDataBreakpointMenu));
		}
		else
		{
			pBar.Add(canDbg, "Remove Breakpoint", CrySearchIml::DeleteButton(), THISBACK(RemoveBreakpointMenu));
		}
		
		pBar.Add("Change Record", CrySearchIml::ChangeRecordIcon(), THISBACK(ChangeRecordSubMenu));
		pBar.Separator();
		pBar.Add("Delete", CrySearchIml::DeleteButton(), THISBACK(DeleteUserDefinedAddress));
	}
}

// Opens up memory dissection window with new dissection dialog opened and selected address filled in.
void CrySearchForm::AddressListEntryMemoryDissection()
{
	// Retrieve a pointer to the selected address table entry.
	const AddressTableEntry* const pEntry = loadedTable[this->mUserAddressList.GetCursor()];
	
	// Execute the memory dissection window using the retrieved address table entry pointer.
	CryMemoryDissectionWindow* cmdw = new CryMemoryDissectionWindow(pEntry);
	cmdw->Execute();
	delete cmdw;
}

// Toggles CrySearch's main window to be always on top or not.
void CrySearchForm::ToggleAlwaysOnTop()
{
	this->TopMost(!this->IsTopMost());
}

void CrySearchForm::ActiveTabWindowChanged()
{
	const int index = ~this->mTabbedDataWindows;
	if (index >= 0 && this->mTabbedDataWindows.GetItem(index).GetText() == "Imports")
	{
		this->mWindowManager.GetImportsWindow()->ModuleRedraw();
	}
}

// Randomizes the window title and sets CrySearch to use menubar label to display the opened process.
void CrySearchForm::RandomizeWindowTitle()
{
	if (this->wndTitleRandomized)
	{
		DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
		this->Title(this->processLoaded ? Format("%s - (%i) %s", (char*)wndTitle, mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()) : (char*)wndTitle);
		this->mOpenedProcess.SetLabel("");
	}
	else
	{
		this->Title(GenerateRandomWindowTitle());
		
		// Set the label in the menu bar to be utilized.
		this->mOpenedProcess.SetLabel(this->processLoaded ? Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()) : "");
	}
	
	this->mMenuStrip.Set(THISBACK(MainMenu));
	this->wndTitleRandomized = !this->wndTitleRandomized;
}

void CrySearchForm::SetDataBreakpointMenu(Bar& pBar)
{
	pBar.Add("Read", THISBACK(SetDataBreakpointOnRead));
	pBar.Add("Write", THISBACK(SetDataBreakpointOnReadWrite));
	pBar.Add("Execute", THISBACK(SetDataBreakpointOnExecute));
}

void CrySearchForm::SearchResultWhenBar(Bar& pBar)
{
	if (this->mScanResults.GetCursor() >= 0 && mMemoryScanner->GetScanResultCount() > 0)
	{
		pBar.Add("Add to address list", CrySearchIml::AddToAddressList(), THISBACK(SearchResultDoubleClicked));
	}
}

void CrySearchForm::SetBreakpointMenuFunction(const HWBP_TYPE type)
{
	const int cursor = this->mUserAddressList.GetCursor();
	HWBP_SIZE size;
	
	// Get breakpoint-wise correct size of data.
	switch (GetDataSizeFromValueType(loadedTable[cursor]->ValueType))
	{
		case 1:
			size = HWBP_SIZE_1;
			break;
		case 2:
			size = HWBP_SIZE_2;
			break;
		case 4:
			size = HWBP_SIZE_4;
			break;
		case 8:
			size = HWBP_SIZE_8;
			break;
	}
	
	// Let's refresh the threads list once more to be sure we have every thread currently active.
	mCrySearchWindowManager->GetThreadWindow()->ClearList();
	mCrySearchWindowManager->GetThreadWindow()->Initialize();
	
	// Set breakpoint on data in each thread in the process.
	mDebugger->SetHardwareBreakpoint(mThreadsList, loadedTable[cursor]->Address, size, type);
}

void CrySearchForm::SetDataBreakpointOnRead()
{
	this->SetBreakpointMenuFunction(HWBP_TYPE_READWRITE);
}

void CrySearchForm::SetDataBreakpointOnReadWrite()
{
	this->SetBreakpointMenuFunction(HWBP_TYPE_WRITE);
}

void CrySearchForm::SetDataBreakpointOnExecute()
{
	this->SetBreakpointMenuFunction(HWBP_TYPE_EXECUTE);
}

void CrySearchForm::RemoveBreakpointMenu()
{
	this->mWindowManager.GetDebuggerWindow()->Cleanup();
	mDebugger->RemoveBreakpoint(loadedTable[this->mUserAddressList.GetCursor()]->Address);
}

void CrySearchForm::PluginsMenuClicked()
{
	CryPluginsWindow* cpw = new CryPluginsWindow();
	cpw->Execute();
	delete cpw;
}

void CrySearchForm::OpenFileMenu()
{
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	FileSel* fs = new FileSel();
	String filter = (char*)appname;
	filter += " Address Tables\t*.csat";
	fs->Types(filter);
	if (fs->ExecuteOpen("Open file..."))
	{
		if (loadedTable.GetCount() > 0 && !Prompt("I need your confirmation", CtrlImg::exclamation()
			, "The address table contains addresses. Are you sure you want to clear them and open a file?", "Yes", "No"))
		{
			delete fs;
			return;
		}
		
		String filename = fs->Get();
		if (!filename.IsEmpty())
		{
			AddressTable::CreateAddressTableFromFile(loadedTable, filename);	
			this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
		}
	}
	
	delete fs;
}

void CrySearchForm::UserDefinedEntryWhenDoubleClicked()
{
	const int row = this->mUserAddressList.GetCursor();
	const int column = this->mUserAddressList.GetClickColumn();
	
	if (row >= 0 && loadedTable.GetCount() > 0)
	{
		switch (column)
		{
#ifdef _WIN64
			case 0: // description
				CryChangeRecordDialog(loadedTable, row, CRDM_DESCRIPTION).Execute();				
				break;
			case 1: // address
				CryChangeRecordDialog(loadedTable, row, CRDM_ADDRESS).Execute();
				break;
			case 2: // value
				CryChangeRecordDialog(loadedTable, row, CRDM_VALUE).Execute();
				break;
			case 3: // type
				CryChangeRecordDialog(loadedTable, row, CRDM_TYPE).Execute();
				break;
#else
			case 0: // description
				CryChangeRecordDialog(loadedTable, row, CRDM_DESCRIPTION).Execute();				
				break;
			case 1: // address
				CryChangeRecordDialog(loadedTable, row, CRDM_ADDRESS).Execute();
				break;
			case 2: // value
				CryChangeRecordDialog(loadedTable, row, CRDM_VALUE).Execute();
				break;
			case 3: // type
				CryChangeRecordDialog(loadedTable, row, CRDM_TYPE).Execute();
				break;
#endif
			default:
				// Compiles cannot know what value GetCursor() returns, so we need to give it the assumption that it won't exceed the cases.
				__assume(0);
		}
	}
}

void CrySearchForm::ToggleAddressTableFreezeThaw()
{
	loadedTable[this->mUserAddressList.GetCursor()]->Frozen = !loadedTable[this->mUserAddressList.GetCursor()]->Frozen;
}

void CrySearchForm::ToggleAddressTableValueView()
{
	viewAddressTableValueHex = !viewAddressTableValueHex;
}

void CrySearchForm::ManuallyAddAddressToTable()
{
	CryChangeRecordDialog(loadedTable, 0, CRDM_MANUALNEW).Execute();
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

void CrySearchForm::AddressListChangeProperty(ChangeRecordDialogMode mode)
{
	const int row = this->mUserAddressList.GetCursor();
	if (row >= 0 && loadedTable.GetCount() > 0)
	{
		switch (mode)
		{
			case CRDM_DESCRIPTION:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, row, CRDM_DESCRIPTION).Execute();
#else
				CryChangeRecordDialog(loadedTable, row, CRDM_DESCRIPTION).Execute();
#endif
				break;
			case CRDM_ADDRESS:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, row, CRDM_ADDRESS).Execute();
#else
				CryChangeRecordDialog(loadedTable, row, CRDM_ADDRESS).Execute();
#endif
				break;
			case CRDM_VALUE:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, row, CRDM_VALUE).Execute();
#else
				CryChangeRecordDialog(loadedTable, row, CRDM_VALUE).Execute();
#endif
				break;
			case CRDM_TYPE:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, row, CRDM_TYPE).Execute();
#else
				CryChangeRecordDialog(loadedTable, row, CRDM_TYPE).Execute();
#endif
				break;
			default:
				// This function will only be called with one of the predefined values so this code path will never be reached.
				__assume(0);
		}
	}
}

void CrySearchForm::SaveFileMenu()
{
	if (!loadedTable.GetFileName().IsEmpty())
	{
		AddressTable::SaveAddressTableToFile(loadedTable, loadedTable.GetFileName());
	}
}

void CrySearchForm::SaveFileAsMenu()
{
	FileSel* fs = new FileSel();
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	fs->Types(Format("%s Address Tables\t*.csat", (char*)appname));
	if (fs->ExecuteSaveAs("Save file..."))
	{
		String filename = fs->Get();
		if (!filename.IsEmpty())
		{
			AddressTable::SaveAddressTableToFile(loadedTable, filename);
		}
	}
	
	delete fs;
}

void CrySearchForm::ShowHideDisasmWindow()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Disassembly");
	CryDisasmCtrl* mDisasmCtrl = this->mWindowManager.GetDisasmWindow();
	if (i >= 0)
	{
		mDisasmCtrl->ClearList();
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	mDisasmCtrl->Initialize();
	this->mTabbedDataWindows.Add(mDisasmCtrl->SizePos(), "Disassembly");
	this->mTabbedDataWindows.Set(*mDisasmCtrl);
}

void CrySearchForm::DeleteUserDefinedAddress()
{
	const int row = this->mUserAddressList.GetCursor();
	if (row >= 0 && loadedTable.GetCount() > 0)
	{
		// Remove breakpoint from data if necessary.
		if (mDebugger)
		{
			mDebugger->RemoveBreakpoint(loadedTable[row]->Address);
		}
		
#ifdef _WIN64
		loadedTable.Remove(ScanInt64(GetAddressTableAddress(row).ToString(), NULL, 16), loadedTable[row]->ValueType);
#else
		loadedTable.Remove(ScanInt(GetAddressTableAddress(row).ToString(), NULL, 16), loadedTable[row]->ValueType);
#endif
		this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	}
}

void CrySearchForm::ClearAddressList()
{
	if (Prompt("I need your confirmation", CtrlImg::exclamation(), "Are you sure you want to clear the address list?", "Yes", "No"))
	{
		// When clearing the list, assurance of all data breakpoints being removed must be made.
		if (mDebugger)
		{
			for (int i = 0; i < loadedTable.GetCount(); i++)
			{
				mDebugger->RemoveBreakpoint(loadedTable[i]->Address);
			}			
		}
		
		// Clear UI and underlying data table structures.
		this->mUserAddressList.Clear();
		loadedTable.Clear();
	}
}

void CrySearchForm::SearchResultDoubleClicked()
{
	const int cursor = this->mScanResults.GetCursor();
	if (cursor < 0 || mMemoryScanner->GetScanResultCount() <= 0)
	{
		return;
	}

	// Retrieve values from virtual columns of the ArrayCtrl.
	const String& value = GetValue(cursor);
	
	// The first value of the scan type is unknown, so + 1 should be the correct value.
	CCryDataType toAddToAddressList;
	switch (GlobalScanParameter->GlobalScanValueType)
	{
		case VALUETYPE_BYTE:
			toAddToAddressList = CRYDATATYPE_BYTE;
			break;
		case VALUETYPE_2BYTE:
			toAddToAddressList = CRYDATATYPE_2BYTES;
			break;
		case VALUETYPE_4BYTE:
			toAddToAddressList = CRYDATATYPE_4BYTES;
			break;
		case VALUETYPE_8BYTE:
			toAddToAddressList = CRYDATATYPE_8BYTES;
			break;
		case VALUETYPE_FLOAT:
			toAddToAddressList = CRYDATATYPE_FLOAT;
			break;
		case VALUETYPE_DOUBLE:
			toAddToAddressList = CRYDATATYPE_DOUBLE;
			break;
		case VALUETYPE_AOB:
			toAddToAddressList = CRYDATATYPE_AOB;
			break;
		case VALUETYPE_STRING:
			toAddToAddressList = CRYDATATYPE_STRING;
			break;
		case VALUETYPE_WSTRING:
			toAddToAddressList = CRYDATATYPE_WSTRING;
			break;
	}
		
	// Try to find the address table entry in the existing table.
	const int curRow = loadedTable.Find(CachedAddresses[cursor].Address, toAddToAddressList);
	
	// Check whether the address table entry already exists.
	if (curRow != -1)
	{
		Prompt("Input Error", CtrlImg::error(), "The selected address is already added to the table.", "OK");
		return;
	}
	
	// Add the entry to the address table.
	const SearchResultCacheEntry& selEntry = CachedAddresses[cursor];
	const AddressTableEntry* newEntry = loadedTable.Add("", selEntry.Address, selEntry.StaticAddress, toAddToAddressList);
	
	// Special behavior for specific types of search results.
	if (toAddToAddressList == CRYDATATYPE_AOB)
	{
		// Retrieve size of byte array
		newEntry->Size = StringToBytes(value).Size;
	}
	else if (toAddToAddressList == CRYDATATYPE_STRING || toAddToAddressList == CRYDATATYPE_WSTRING)
	{
		newEntry->Size = value.GetLength();
	}
	
	// If there is no process loaded, set the value to invalid.
	if (!mMemoryScanner->GetProcessId())
	{
		newEntry->Value = "???";
	}
	
	// Refresh address table in user interface.
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

void CrySearchForm::MemorySearch()
{
	if (!this->processLoaded)
	{
		Prompt("Input Error", CtrlImg::error(), "There is no process opened. Please open a process first.", "OK");
		return;
	}
	
	CryNewScanForm* newScan = new CryNewScanForm(true, CrySearchIml::SearchMemoryMenu());
	if (newScan->Execute() != 10)
	{
		delete newScan;
		return;
	}
	
	delete newScan;
	this->ClearScanResultsWithoutWarning();

#ifdef _MULTITHREADED
	Thread::Start(THISBACK1(StartMemoryScanReliefGUI, true));
#else
	StartMemoryScanReliefGUI(true);
#endif
}

void CrySearchForm::RefreshSearchResults()
{
	if (!this->processLoaded)
	{
		Prompt("Input Error", CtrlImg::error(), "There is no process opened. Please open a process first.", "OK");
		return;
	}
	
	CryNewScanForm newScan(false, CrySearchIml::SearchMemoryMenu());
	if (newScan.Execute() != 10)
	{
		return;
	}
	
	this->mScanResults.Clear();

#ifdef _MULTITHREADED
	Thread::Start(THISBACK1(StartMemoryScanReliefGUI, false));
#else
	StartMemoryScanReliefGUI(false);
#endif
}

// Starts a next scan with a hotkey press.
void CrySearchForm::StartNextScanHotkey()
{
	this->mScanResults.Clear();
	
#ifdef _MULTITHREADED
	Thread::Start(THISBACK1(StartMemoryScanReliefGUI, false));
#else
	StartMemoryScanReliefGUI(false);
#endif
}

void CrySearchForm::StartMemoryScanReliefGUI(bool FirstScan)
{
	switch (GlobalScanParameter->GlobalScanValueType)
	{
		case VALUETYPE_BYTE:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<Byte>();
			}
			else
			{
				mMemoryScanner->NextScan<Byte>();
			}
			break;
		case VALUETYPE_2BYTE:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<short>();
			}
			else
			{
				mMemoryScanner->NextScan<short>();
			}
			break;
		case VALUETYPE_4BYTE:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<int>();
			}
			else
			{
				mMemoryScanner->NextScan<int>();
			}
			break;
		case VALUETYPE_8BYTE:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<__int64>();
			}
			else
			{
				mMemoryScanner->NextScan<__int64>();
			}
			break;
		case VALUETYPE_FLOAT:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<float>();
			}
			else
			{
				mMemoryScanner->NextScan<float>();
			}
			break;
		case VALUETYPE_DOUBLE:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<double>();
			}
			else
			{
				mMemoryScanner->NextScan<double>();
			}
			break;
		case VALUETYPE_STRING:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<String>();
			}
			else
			{
				mMemoryScanner->NextScan<String>();
			}
			break;
		case VALUETYPE_WSTRING:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<WString>();
			}
			else
			{
				mMemoryScanner->NextScan<WString>();
			}
			break;
		case VALUETYPE_AOB:
			if (FirstScan)
			{
				mMemoryScanner->FirstScan<ArrayOfBytes>();
			}
			else
			{
				mMemoryScanner->NextScan<ArrayOfBytes>();
			}
			break;
	}
}

void CrySearchForm::OpenProcessMenu()
{
	CryProcessEnumeratorForm* cpef = new CryProcessEnumeratorForm(CrySearchIml::AttachToProcessMenu());
	if (cpef->Execute() == 10)
	{
		this->WhenProcessOpened(cpef->GetSelectedProcess());
	}
	
	delete cpef;
}

void CrySearchForm::CloseProcessMenu()
{
	if (this->CloseProcess())
	{
		// Tell the loaded plugins that the currently loaded process has closed.
		mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_PROCESS_CLOSED, NULL);
	}
}

bool CrySearchForm::CloseProcess()
{
	if (mMemoryScanner->IsScanRunning())
	{
		Prompt("Scanning Error", CtrlImg::error(), "Cannot close the process because a scan is running at the moment.", "OK");
		return false;
	}

	if (!this->wndTitleRandomized)
	{
		DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
		this->Title((char*)wndTitle);
	}
	
	this->mOpenedProcess.SetLabel("");
	
	// If the process was terminated, the warning should not be shown, it is annoying to the user.
	if (!this->ProcessTerminated)
	{
	  	this->ClearScanResultsWithoutWarning();
	}
	else
	{
		this->ClearScanResults();
	}
	
	// Set all address entries to invalid values. Since the timer stopped it does not automatically update this anymore.
	for (int i = 0; i < loadedTable.GetCount(); i++)
	{
		loadedTable[i]->Value = "???";
	}
	
	// Clean up process-dependent resources to make sure nothing will cause undefined behavior.
	if (mMemoryScanner->GetProcessId())
	{
		delete mPeInstance;
		mPeInstance = NULL;
		
		mDebugger->Stop();
		delete mDebugger;
		mDebugger = NULL;
	}
	
	// Close handles.
	mMemoryScanner->CloseProcess();
	this->processLoaded = false;
	
	// Disable process-only toolbars and menus.
	this->mMenuStrip.Set(THISBACK(MainMenu));
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	// Free process-bound resources.
	this->mWindowManager.ClearWindows();
	
	this->mTabbedDataWindows.Reset();
	
	// Kill running timers.
	KillTimeCallback(10);

	// Clean process name inside address table.
	loadedTable.ClearProcessName();
	
	// Refresh address table for user interface.
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	
	return true;
}

void CrySearchForm::ExitApplication()
{
	this->Close();
}

void CrySearchForm::SettingsButtonClicked()
{
	CrySearchSettingsDialog* cssd = new CrySearchSettingsDialog();
	cssd->Execute();
	delete cssd;
	
	this->LinkHotkeysToActions();
	
	// If the hotkeys are enabled, reinstate the callback for the next poll session.
	if (SettingsFile::GetInstance()->GetEnableHotkeys())
	{
		KillTimeCallback(20);
		SetTimeCallback(100, THISBACK(CheckKeyPresses), 20);
	}
}

void CrySearchForm::DebuggerAttachMenu()
{
	mDebugger->Start();
	this->ToggleDebuggerWindow();
}

void CrySearchForm::DebuggerDetachMenu()
{
	mDebugger->Stop();
	this->ToggleDebuggerWindow();
}

void CrySearchForm::DebugWindowErrorOccured()
{
	this->ToggleDebuggerWindow();
}

void CrySearchForm::CodeGenerationButtonClicked()
{
	CryCodeGenerationForm* ccgf = new CryCodeGenerationForm();
	ccgf->Execute();
	delete ccgf;
}

void CrySearchForm::MemoryDissectionButtonClicked()
{
	CryMemoryDissectionWindow* cmdw = new CryMemoryDissectionWindow(NULL);
	cmdw->Execute();
	delete cmdw;
}

void CrySearchForm::ViewSystemHandlesButtonClicked()
{
	CrySystemHandleInformationWindow* cshiw = new CrySystemHandleInformationWindow(CrySearchIml::ViewHandlesButton());
	cshiw->Execute();
	delete cshiw;
}

void CrySearchForm::ViewPEBButtonClicked()
{
	CryProcessEnvironmentBlockWindow* cpebw = new CryProcessEnvironmentBlockWindow(CrySearchIml::AboutButton());
	cpebw->Execute();
	delete cpebw;
}

void CrySearchForm::AllocateMemoryButtonClicked()
{
	AllocateMemoryDataStruct dataStruct;
	CryAllocateMemoryWindow* allocWnd = new CryAllocateMemoryWindow(&dataStruct);
	
	if (allocWnd->Execute() != 10)
	{
		delete allocWnd;
		return;
	}
	
	SIZE_T outVirtualAddress;
	switch (CryAllocateProcessMemory(mMemoryScanner->GetHandle(), dataStruct.MemorySize, dataStruct.BlockProtection, &outVirtualAddress))
	{
		case 0: // succeeded
#ifdef _WIN64
			if (mMemoryScanner->IsX86Process())
			{
				PromptOK(Format("Memory succesfully allocated!&&Virtual Address: %lX", (__int64)outVirtualAddress));
			}
			else
			{
				PromptOK(Format("Memory succesfully allocated!&&Virtual Address: %llX", (__int64)outVirtualAddress));
			}
#else
			PromptOK(Format("Memory succesfully allocated!&&Virtual Address: %lX", (int)outVirtualAddress));
#endif
			break;
		case -1: // virtualallocex failed
			Prompt("Allocation Error", CtrlImg::error(), "The memory was not allocated because the system call failed. This could be due to incorrect memory size input.", "OK");
			break;
	}
	
	delete allocWnd;
}

void CrySearchForm::ViewThreadsButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Threads");
	CryThreadWindow* threadWindow = this->mWindowManager.GetThreadWindow();
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	threadWindow->Initialize();
	this->mTabbedDataWindows.Add(threadWindow->SizePos(), "Threads");
	this->mTabbedDataWindows.Set(*threadWindow);
}

void CrySearchForm::ViewModulesButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Modules");
	CryModuleWindow* moduleWindow = this->mWindowManager.GetModuleWindow();
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	moduleWindow->Initialize();
	this->mTabbedDataWindows.Add(moduleWindow->SizePos(), "Modules");
	this->mTabbedDataWindows.Set(*moduleWindow);
}

void CrySearchForm::ViewGeneralButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "General");
	CryPEWindow* peWindow = this->mWindowManager.GetPEWindow();
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	peWindow->Initialize();
	this->mTabbedDataWindows.Add(peWindow->SizePos(), "General");
	this->mTabbedDataWindows.Set(*peWindow);
}

void CrySearchForm::ViewImportsButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Imports");
	CryImportsWindow* importsWindow = this->mWindowManager.GetImportsWindow();
	if (i >= 0)
	{
		LoadedProcessPEInformation.ClearImportTable();
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	importsWindow->Initialize();
	this->mTabbedDataWindows.Add(importsWindow->SizePos(), "Imports");
	this->mTabbedDataWindows.Set(*importsWindow);
}

void CrySearchForm::ToggleDebuggerWindow()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Debugger");
	CryDebuggerWindow* debuggerWindow = this->mWindowManager.GetDebuggerWindow();
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	debuggerWindow->Initialize();
	this->mTabbedDataWindows.Add(debuggerWindow->SizePos(), "Debugger");
	this->mTabbedDataWindows.Set(*debuggerWindow);
}

void CrySearchForm::ExecuteCrashHandlerWindow(const String& msg)
{
	volatile bool comp = false;
	PostCallback(THISBACK2(ExecuteCrashHandlerWindowSafe, msg, &comp));
	while (!comp)
	{
		Sleep(25);
	}
}

void CrySearchForm::ExecuteCrashHandlerWindowSafe(const String& msg, volatile bool* const comp)
{
	CryCrashHandlerWindow* cchw = new CryCrashHandlerWindow(msg);
	cchw->Execute();
	delete cchw;
	*comp = true;
}

void CrySearchForm::AboutCrySearch()
{
	CrySearchAboutDialog().Execute();
}

void CrySearchForm::ClearScanResults()
{
	if (this->mScanResults.GetCount() > 0 && !Prompt("I need your confirmation", CtrlImg::exclamation()
		, "Do you want to keep the current scan results?", "Yes", "No"))
	{
		this->mScanResults.Clear();
		mMemoryScanner->ClearSearchResults();
		this->mSearchResultCount.SetLabel("Search Results: 0");
	}
}

void CrySearchForm::ClearScanResultsWithoutWarning()
{
	this->mScanResults.Clear();
	mMemoryScanner->ClearSearchResults();
	
	this->mSearchResultCount.SetLabel("Search Results: 0");
}

bool CrySearchForm::InitializeProcessUI()
{
#ifndef _WIN64
	this->mWindowManager.GetModuleWindow()->Initialize();
	this->mWindowManager.GetThreadWindow()->Initialize();

	// Check the architecture of the loaded process. Under x64, processes can cause trouble.
	if (mMemoryScanner->IsX86Process())
	{
		// Instantiate new PE class.
		mPeInstance = new PortableExecutable32();
		mDebugger = new CryDebugger32();
		this->mWindowManager.GetPEWindow()->Initialize();
		this->mWindowManager.GetImportsWindow()->Initialize();
		this->mWindowManager.GetDisasmWindow()->Initialize();
	}
	else
	{
		const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
		Prompt("Load Error", CtrlImg::error(), Format("Failed to open the selected process because it is 64-bit. Use %s x64 to open it instead.", (char*)appname), "OK");
		mMemoryScanner->CloseProcess();
		PostCallback(THISBACK(OpenProcessMenu));
		return false;
	}
#else
	this->mWindowManager.GetModuleWindow()->Initialize();
	this->mWindowManager.GetThreadWindow()->Initialize();
	
	if (mMemoryScanner->IsX86Process())
	{
		mPeInstance = new PortableExecutable32();
		mDebugger = new CryDebugger32();
	}
	else
	{
		mPeInstance = new PortableExecutable64();
		mDebugger = new CryDebugger64();
	}
	
	this->mWindowManager.GetPEWindow()->Initialize();
	this->mWindowManager.GetImportsWindow()->Initialize();
	this->mWindowManager.GetDisasmWindow()->Initialize();
#endif
	this->mWindowManager.GetDebuggerWindow()->Initialize();
	
	// Still here so the process loaded succesfully. Update user interface and prepare tabs.
	this->processLoaded = true;
	this->mToolStrip.Set(THISBACK(ToolStrip));

	// Set timer callback that runs the address list update sequence.
	SetTimeCallback(SettingsFile::GetInstance()->GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
	
	// Succesfully initialized user interface.
	return true;
}

void CrySearchForm::WhenProcessOpened(Win32ProcessInformation* pProc)
{
	// Check whether a process was previously opened.
	if (mMemoryScanner->GetProcessId())
	{
		// A process was opened, free used resources and close it.
		if (!CloseProcess())
		{
			return;
		}
	}
	
	// Process ID is -1, create process using ExeTitle.
	if (pProc->ProcessId == -1)
	{
		// Create process with memory scanner class.
		if (mMemoryScanner->InitializeNewProcess(pProc->ExeTitle, pProc->UserInterfaceFlags, pProc->ProcessArguments, &pProc->ProcessId))
		{
			// Wait for the process to be fully started, otherwise initialization steps will fail.
			Sleep(250);
			
			// Check if the process actually started correctly, if it didn't, the procedure failed.
			if (IsProcessActive(mMemoryScanner->GetHandle()))
			{
				if (!this->InitializeProcessUI())
				{
					return;
				}
				
				if (this->wndTitleRandomized)
				{
					this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
				}
				else
				{
					DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
					this->Title(Format("%s - (%i) %s", (char*)wndTitle, pProc->ProcessId, mMemoryScanner->GetProcessName()));
					this->mOpenedProcess.SetLabel("");
				}
				
				this->mMenuStrip.Set(THISBACK(MainMenu));
					
				this->mTabbedDataWindows.Add(this->mWindowManager.GetPEWindow()->SizePos(), "General");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetDisasmWindow()->SizePos(), "Disassembly");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetImportsWindow()->SizePos(), "Imports");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetThreadWindow()->SizePos(), "Threads");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetModuleWindow()->SizePos(), "Modules");
				
				this->ProcessTerminated = false;
				SetTimeCallback(250, THISBACK(CheckProcessTermination), 30);
				
				// Set process name in the address table using the value from the FileSel.
				loadedTable.SetProcessName(pProc->ExeTitle);
			}
			else
			{
				// CreateProcess succeeded, but the process is not started succesfully. For example: write.exe starts wordpad.exe and then terminates.
				Prompt("Load Error", CtrlImg::error(), "The process started succesfully but terminated before initialization. Possibly the process started another process and terminated.", "OK");
				mMemoryScanner->CloseProcess();
				PostCallback(THISBACK(OpenProcessMenu));
			}
		}
		else
		{
			// CreateProcess failed, no process is loaded.
			Prompt("Load Error", CtrlImg::error(), "Failed to create the process.", "OK");
			PostCallback(THISBACK(OpenProcessMenu));
		}
	}
	else
	{
		// Use process ID to open an existing process.
		if (mMemoryScanner->InitializeExistingProcess(pProc->ProcessId, pProc->ExeTitle))
		{
			if (!this->InitializeProcessUI())
			{
				return;
			}
					
			if (this->wndTitleRandomized)
			{
				this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
			}
			else
			{
				DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
				this->Title(Format("%s - (%i) %s", (char*)wndTitle, pProc->ProcessId, mMemoryScanner->GetProcessName()));
				this->mOpenedProcess.SetLabel("");
			}
			
			this->mMenuStrip.Set(THISBACK(MainMenu));
			
			// Add tabs to the tabcontrol.
			this->mTabbedDataWindows.Add(this->mWindowManager.GetPEWindow()->SizePos(), "General");
			this->mTabbedDataWindows.Add(this->mWindowManager.GetDisasmWindow()->SizePos(), "Disassembly");
			this->mTabbedDataWindows.Add(this->mWindowManager.GetImportsWindow()->SizePos(), "Imports");
			this->mTabbedDataWindows.Add(this->mWindowManager.GetThreadWindow()->SizePos(), "Threads");
			this->mTabbedDataWindows.Add(this->mWindowManager.GetModuleWindow()->SizePos(), "Modules");
			
			this->ProcessTerminated = false;
			SetTimeCallback(250, THISBACK(CheckProcessTermination), 30);
			
			// Since the process name is either retrieved or known, setting it here should not bring any problems.
			loadedTable.SetProcessName(mMemoryScanner->GetProcessName());
		}
	}
	
	// Resolve relative addresses. An address table may be loaded before the process was loaded, hence the entries weren't yet resolved.
	AddressTable::ResolveRelativeEntries(loadedTable);
	
	// Tell the loaded plugins that a process has loaded. The PID is passed into the plugin.
	mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_PROCESS_OPENED, (void*)pProc->ProcessId);
}

void CrySearchForm::ScannerScanStarted(int threadCount)
{
	PostCallback(THISBACK1(ScannerScanStartedThreadSafe, threadCount));
}

void CrySearchForm::ScannerScanStartedThreadSafe(int threadCount)
{
	this->mToolStrip.Set(THISBACK(ToolStrip));
	this->mScanningProgress.Show();
	this->mScanningProgress.Set(0, threadCount);
}

void CrySearchForm::ScannerUserInterfaceUpdate(Atomic threadCount)
{
	PostCallback(THISBACK1(ScannerUserInterfaceUpdateThreadSafe, threadCount));
}

void CrySearchForm::ScannerUserInterfaceUpdateThreadSafe(Atomic threadCount)
{
	this->mScanningProgress.Set(threadCount);
}

void CrySearchForm::ScannerErrorOccured(MemoryScannerError error)
{
	PostCallback(THISBACK1(ScannerErrorOccuredThreadSafe, error));
}

void CrySearchForm::ScannerErrorOccuredThreadSafe(MemoryScannerError error)
{
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	switch (error)
	{
		case OPENPROCESSFAILED:
			// Kill timer callback, otherwise two error messages will pop up.
			KillTimeCallback(30);
			
			Prompt("Process Error", CtrlImg::error(), Format("Could not open the selected process. The process is either protected or 64-bit."\
				" To open a protected process, try running %s as Administrator.", (char*)appname), "OK");
			PostCallback(THISBACK(OpenProcessMenu));
			break;
		case PROCESSWASTERMINATED:
			// Kill timer callback, otherwise the stack will overflow.
			KillTimeCallback(30);
			
			Prompt("Process Error", CtrlImg::error(), "It looks like the process has been terminated. The process will now be closed.", "OK");
			this->CloseProcessMenu();
			break;
		case NOREADABLEMEMORYFOUND:
			Prompt("Scanning Error", CtrlImg::error(), "Could not find any readable memory page. Scan aborted.", "OK");
			break;
		case DATAFILENOTFOUND:
			Prompt("Scanning Error", CtrlImg::error(), "The temp file containing results could not be read. Scan aborted.", "OK");
			break;
		case NATIVEROUTINEGETPROCFAILED:
			Prompt("Scanning Error", CtrlImg::error(), "The location of the native procedure could not be retrieved from ntdll.dll.", "OK");
			break;
	}
}

void CrySearchForm::ScannerCompletedScan()
{
	PostCallback(THISBACK(ScannerCompletedThreadSafe));
}

void CrySearchForm::ScannerCompletedThreadSafe()
{
	if (mMemoryScanner->GetScanResultCount() > MEMORYSCANNER_CACHE_LIMIT)
	{
		this->mScanResults.SetVirtualCount(MEMORYSCANNER_CACHE_LIMIT);
		this->mSearchResultCount.SetLabel(Format("Search Results: %i (100.000 results shown)", mMemoryScanner->GetScanResultCount()));
	}
	else
	{
		this->mScanResults.SetVirtualCount(mMemoryScanner->GetScanResultCount());
		this->mSearchResultCount.SetLabel(Format("Search Results: %i", mMemoryScanner->GetScanResultCount()));
	}
	
	// Create distinction between relative and dynamic addresses.
	CrySearchArrayCtrl* const ctrl = this->GetSearchResultCtrl();
	const int aCount = CachedAddresses.GetCount();
	for (int a = 0; a < aCount; ++a)
	{
		if (CachedAddresses[a].StaticAddress)
		{
			// Set green display color for relative addresses.
			ctrl->SetRowDisplay(a, GreenDisplayDrawInstance);
		}
	}
	
	this->mScanningProgress.Hide();
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	// Cheat Engine has this nice beep when a scan completes, why shouldn't I? :)
	BeepExclamation();
}

// ---------------------------------------------------------------------------------------------

// Returns a pointer to the window manager associated to CrySearchForm.
CrySearchWindowManager* CrySearchForm::GetWindowManager()
{
	return &this->mWindowManager;
}

// Returns a pointer to the search result control. Friend methods may need to set the display property.
CrySearchArrayCtrl* CrySearchForm::GetSearchResultCtrl()
{
	return &this->mScanResults;
}

// Sets the currently active (on top) tab window.
// Returns true if the window was found and hence moved to front. Returns false if the window was not found.
bool CrySearchForm::SetActiveTabWindow(const String& wndText)
{
	const int i = IsTabPageOpened(this->mTabbedDataWindows, wndText);
	if (i >= 0)
	{
		this->mTabbedDataWindows.Set(i);
		return true;
	}
	
	return false;
}

// ---------------------------------------------------------------------------------------------

GUI_APP_MAIN
{
	CrySearchForm* frm;
	
	// Wire up the crash handler.
	SetUnhandledExceptionFilter(CrashHandler);
	
	// Get the command line. In case a .csat file was opened, the first argument is the path to the file.
	const Vector<String>& cmdline = CommandLine();
	if (cmdline.GetCount() > 0)
	{
		frm = new CrySearchForm(cmdline[0]);
	}
	else
	{
		frm = new CrySearchForm(NULL);
	}

	// Delete temporary files from any earlier run, which might have crashed.
	DeleteTemporaryFiles();
	
	// Run main window.
	mCrySearchWindowManager = frm->GetWindowManager();
	frm->Run();
	delete frm;

	// Force destruction of global objects to restore states of opened processes.
	CryGlobalDestruct();
	
	// Release the memory scanner and other related resources.
	delete GlobalScanParameter;

	// Delete temporary files used before quitting.
	DeleteTemporaryFiles();
	
	// Close all threads to make the application able to exit safely.
	ExitProcess(0);
}