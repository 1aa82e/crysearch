// Nessecary dialog includes and IML provider for imaging.
#include "CrySearchForm.h"
#include "CrySettingsDialog.h"
#include "CrySearchAboutDialog.h"
#include "CryProcessEnumeratorForm.h"
#include "CryNewScanForm.h"
#include "CryAllocateMemoryWindow.h"
#include "CryFillMemoryWindow.h"
#include "CryCodeGenerationForm.h"
#include "CryMemoryDissectionWindow.h"
#include "CryProcessEnvironmentBlockWindow.h"
#include "CrySystemHandleInformationWindow.h"
#include "CryHeapWalkDialog.h"
#include "CryPluginsWindow.h"
#include "CryBruteforcePIDWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// Global source IML file declaration. Imaging in the GUI depends on this.
#define IMAGECLASS CrySearchIml
#define IMAGEFILE "CrySearch.iml"
#include <Draw/iml_source.h>

// Time callback type definitions.
#define MEMORY_SCANNER_COMPLETION_TIMECALLBACK	5
#define ADDRESS_TABLE_UPDATE_TIMECALLBACK		10
#define HOTKEY_TIMECALLBACK						20
#define UPDATE_RESULTS_TIMECALLBACK				21
#define PROCESS_TERMINATION_TIMECALLBACK		30

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

// Gets the string representation of a value, given its address, value type, and extra conditions.
String GetValueRepresentationString(const SIZE_T address, const bool hex, const CCryDataType valueType, const int optSize)
{
	if (valueType == CRYDATATYPE_BYTE)
	{
		Byte value;
		if (mMemoryScanner->Peek(address, sizeof(Byte), &value))
		{
			return hex ? FormatHexadecimalIntSpecial(value) : FormatIntSpecial(value);
		}
	}
	else if (valueType == CRYDATATYPE_2BYTES)
	{
		short value;
		if (mMemoryScanner->Peek(address, sizeof(short), &value))
		{
			return hex ? FormatHexadecimalIntSpecial(value) : FormatIntSpecial(value);
		}
	}
	else if (valueType == CRYDATATYPE_4BYTES)
	{
		int value;
		if (mMemoryScanner->Peek(address, sizeof(int), &value))
		{
			return hex ? FormatHexadecimalIntSpecial(value) : FormatIntSpecial(value);
		}
	}
	else if (valueType == CRYDATATYPE_8BYTES)
	{
		__int64 value;
		if (mMemoryScanner->Peek(address, sizeof(__int64), &value))
		{
			return hex ? FormatHexadecimalIntSpecial64(value) : FormatIntSpecial64(value);
		}
	}
	else if (valueType == CRYDATATYPE_FLOAT)
	{
		float value;
		if (mMemoryScanner->Peek(address, sizeof(float), &value))
		{
			return DblStr(value);
		}
	}
	else if (valueType == CRYDATATYPE_DOUBLE)
	{
		double value;
		if (mMemoryScanner->Peek(address, sizeof(double), &value))
		{
			return DblStr(value);
		}
	}
	else if (valueType == CRYDATATYPE_STRING)
	{
		String value;
		if (mMemoryScanner->PeekA(address, optSize, value))
		{
			return value;
		}
	}
	else if (valueType == CRYDATATYPE_WSTRING)
	{
		WString value;
		if (mMemoryScanner->PeekW(address, optSize, value))
		{
			return value.ToString();
		}
	}
	else if (valueType == CRYDATATYPE_AOB)
	{
		ArrayOfBytes value;
		if (mMemoryScanner->PeekB(address, optSize, value))
		{
			return BytesToString(value.Data, optSize);
		}
	}
	
	// The value of the search result could not be read. The presented value is therefore unknown.
	return "???";
}

// ---------------------------------------------------------------------------------------------

// Gets the string representation of the address of a search result.
String GetAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(CachedAddresses[index].Address);
#else
	return FormatHexadecimalIntSpecial(CachedAddresses[index].Address);
#endif
}

// Gets the string representation of the value of a search result.
String GetValue(const int index)
{
	if (!mMemoryScanner->IsScanRunning())
	{
		return GetValueRepresentationString(CachedAddresses[index].Address, GlobalScanParameter->CurrentScanHexValues, GlobalScanParameter->GlobalScanValueType
			, GlobalScanParameter->GlobalScanValueType == CRYDATATYPE_AOB ? GlobalScanParameter->ValueSize : CachedAddresses[index].StringLength);
	}
	
	// The value of the search result could not be read. The presented value is therefore unknown.
	return "???";
}

// Gets the description of an address table entry.
String GetAddressTableDescription(const int index)
{
	return loadedTable[index]->Description;
}

// Gets the string representation of the address of an address table entry.
String GetAddressTableAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(loadedTable[index]->Address);
#else
	return FormatHexadecimalIntSpecial(loadedTable[index]->Address);
#endif
}

// Gets the string representation of the value of an address table entry.
String GetAddressTableValue(const int index)
{
	// Only read the value of address table entries if a process is opened.
	const AddressTableEntry* const entry = loadedTable[index];
	if (mMemoryScanner->GetProcessId())
	{
		entry->Value = GetValueRepresentationString(entry->Address, viewAddressTableValueHex, entry->ValueType, entry->Size);
		return entry->Value;
	}
	
	// The value of the address table entry could not be read. The presented value is therefore unknown.
	entry->Value =  "???";
	return entry->Value;
}

// Gets the valuetype of an address table entry.
String GetAddressTableValueType(const int index)
{
	return GetCrySearchDataTypeRepresentation(loadedTable[index]->ValueType);
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
	this->mUserAddressList.RemovalRoutine = THISBACK(AddressTableRemovalRoutine);

	this->mSearchResultsPanel
		<< this->mSearchResultCount.SetLabel("Search Results: 0").HSizePosZ(5, 5).TopPos(5, 20)
		<< this->mScanningProgress.RightPos(5, 120).TopPos(5, 20)
		<< this->mScanResults.MultiSelect().HSizePosZ(5, 5).VSizePosZ(30, 0)
	;
	
	this->mUserAddressPanel << this->mUserAddressList.MultiSelect().HSizePos(5, 5).VSizePos(5);
	
	this->mScanningProgress.Hide();
	this->mTabbedDataWindows.WhenSet = THISBACK(ActiveTabWindowChanged);
	
	*this
		<< this->mMainSplitter.Vert(this->mInputScanSplitter.Horz(this->mSearchResultsPanel, this->mUserAddressPanel)
			, this->mTabbedDataWindows.SizePos())
	;
	
	// Sets the position and resize thresholds for the main window splitting controls.
	this->SetMainSplitterPosition();
	this->mMainSplitter.SetMinPixels(0, 100);
	this->mMainSplitter.SetMinPixels(1, 100);
	this->mInputScanSplitter.SetMinPixels(0, 300);
	this->mInputScanSplitter.SetMinPixels(1, 250);
	
	// If settings configuration file is not found, create a new one using default settings.
	if (!SettingsFile::ConfigFileExists() || !SettingsFile::GetInstance()->Initialize())
	{
		//Prompt("Settings Error", CtrlImg::exclamation(), "The settings file was not found or corrupt, and has been overwritten with the defaults. If this is your first run, you can ignore this warning.", "OK");
		SettingsFile::GetInstance()->DefaultSettings();
	}
	
	// Initiate the memory scanner class, the most important part of CrySearch.
	mMemoryScanner->ErrorOccured = THISBACK(ScannerErrorOccured);
	mMemoryScanner->UpdateScanningProgress = THISBACK(ScannerUserInterfaceUpdate);
	mMemoryScanner->ScanStarted = THISBACK(ScannerScanStarted);
	
	// Initialize the plugin system.
	mPluginSystem = PluginSystem::GetInstance();
	mPluginSystem->RetrieveAndLoadAllPlugins();
	
	// Validate plugin-defined routine indices and act accordingly.
	const int opr = SettingsFile::GetInstance()->GetOpenProcessRoutine();
	const int rpm = SettingsFile::GetInstance()->GetReadMemoryRoutine();
	const int wpm = SettingsFile::GetInstance()->GetWriteMemoryRoutine();
	const int pm = SettingsFile::GetInstance()->GetProtectMemoryRoutine();
	const int pluginCount = mPluginSystem->GetPluginCount();
	bool changed = false;
	
	// If the settings-saved routine index is out of the current bounds, a previously used routine-plugin
	// may have failed at this moment, or the designated plugin has been removed from the plugins directory.
	// We take no chance and set the default routine for use.
	const int pluginCountTwo = pluginCount + 2;
	if ((pluginCount == 0 && (opr > 1 || rpm > 1 || wpm > 1 || pm > 1))
		|| (opr > pluginCountTwo || rpm > pluginCountTwo || wpm > pluginCountTwo || pm > pluginCountTwo))
	{
		SettingsFile::GetInstance()->SetOpenProcessRoutine();
		SettingsFile::GetInstance()->SetReadMemoryRoutine();
		SettingsFile::GetInstance()->SetWriteMemoryRoutine();
		SettingsFile::GetInstance()->SetProtectMemoryRoutine();
		changed = true;
	}
	
	// If the value was changed, let the user know.
	if (changed)
	{
		SettingsFile::GetInstance()->Save();
		Prompt("Warning", CtrlImg::exclamation(), "The settings file contained core invalid routine indices. The invalid ones have been restored to default.", "OK");
	}
	
	// The settings file saves some routines too. Set the correct routines.
	CrySearchRoutines.InitializeRoutines();
	
	// If one of more NTDLL functions were not succesfully retrieved, notify the user about it.
	if (CrySearchRoutines.ErrorOccured())
	{
		Prompt("Behavioral Warning", CtrlImg::exclamation(), Format("One or more NTDLL functions were not retrieved succesfully. %s may behave unpredictable from here.", String((char*)wndTitle, 9)), "OK");
	}
	
	// Make sure the module manager is initialized.
	mModuleManager = ModuleManager::GetInstance();
	
	// Set timer that runs keeping track of hotkeys.
	SetTimeCallback(100, THISBACK(CheckKeyPresses), HOTKEY_TIMECALLBACK);

	// Set timer callback that runs the address list update sequence.
	SetTimeCallback(SettingsFile::GetInstance()->GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), ADDRESS_TABLE_UPDATE_TIMECALLBACK);
	
	// Set timer callback that runs the search results update sequence.
	SetTimeCallback(1000, THISBACK(SearchResultListUpdater), UPDATE_RESULTS_TIMECALLBACK);
	
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

// The main window destructor.
CrySearchForm::~CrySearchForm()
{
	// Stop the timer callbacks that are running.
	KillTimeCallback(ADDRESS_TABLE_UPDATE_TIMECALLBACK);
	KillTimeCallback(HOTKEY_TIMECALLBACK);
	KillTimeCallback(PROCESS_TERMINATION_TIMECALLBACK);
}

// ---------------------------------------------------------------------------------------------

// Populates the main application window menu strip.
void CrySearchForm::MainMenu(Bar& pBar)
{
	pBar.Add("File", THISBACK(FileMenu));
	pBar.Add("Edit", THISBACK(EditMenu));
	pBar.Add("Tools", THISBACK(ToolsMenu));
	
	// Some menu items should only be added when a process has been opened.
	if (this->processLoaded && mModuleManager->GetModuleCount())
	{
		pBar.Add("Debugger", THISBACK(DebuggerMenu));
	}
	
	pBar.Add("Window", THISBACK(WindowMenu));
	pBar.Add("Help", THISBACK(HelpMenu));
	
	// When the window title is randomized the opened process should be listed in the label below the bar.
	pBar.MenuGapRight();
	pBar.Add(this->mOpenedProcess.SetAlign(ALIGN_RIGHT), 200);
}

// Populates the main application window toolstrip.
void CrySearchForm::ToolStrip(Bar& pBar)
{
	pBar.Add("Open Process", CrySearchIml::AttachToProcessMenu(), THISBACK(OpenProcessMenu));
	pBar.Add(this->processLoaded && !mMemoryScanner->IsScanRunning(), "Search", CrySearchIml::SearchMemoryMenu(), THISBACK(MemorySearch));
	pBar.Add(this->processLoaded && !mMemoryScanner->IsScanRunning() && mScanResults.GetCount() > 0, "Refresh search results", CrySearchIml::NextScanMenu(), THISBACK(RefreshSearchResults));
}

// Populates the file menu bar.
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

// Populates the menu bar for data editing operations.
void CrySearchForm::EditMenu(Bar& pBar)
{
	pBar.Add((this->mScanResults.GetCount() > 0), "Clear Scan Results", THISBACK(ClearScanResultsWithoutWarning));
	pBar.Add((this->mUserAddressList.GetCount() > 0), "Clear Address List", THISBACK(ClearAddressList));
	
	pBar.Separator();
	pBar.Add("Settings", CrySearchIml::SettingsButton(), THISBACK(SettingsButtonClicked));
}

// Populates the menu bar for tools.
void CrySearchForm::ToolsMenu(Bar& pBar)
{
	if (this->processLoaded)
	{
		pBar.Add("View PEB", CrySearchIml::AboutButton(), THISBACK(ViewPEBButtonClicked));
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "View Handles", CrySearchIml::ViewHandlesButton(), THISBACK(ViewSystemHandlesButtonClicked));
		pBar.Separator();
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Allocate Memory", CrySearchIml::AllocateMemoryButton(), THISBACK(AllocateMemoryButtonClicked));
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Fill Memory", THISBACK(FillMemoryButtonClicked));
		pBar.Add("Memory Dissection", CrySearchIml::MemoryDissection(), THISBACK(MemoryDissectionButtonClicked));
		pBar.Add("View Heap Information", CrySearchIml::HeapWalkSmall(), THISBACK(HeapWalkMenuClicked));
		pBar.Separator();
		pBar.Add((this->mUserAddressList.GetCount() > 0), "Code Generation", CrySearchIml::CodeGenerationButton(), THISBACK(CodeGenerationButtonClicked));
	}
	
	// These menu items can be added regardless of the program state.
	pBar.Add(!this->processLoaded, "Brute-Force PID", CrySearchIml::BruteForceSmall(), THISBACK(BruteForcePIDClicked));
	pBar.Separator();
	pBar.Add("Plugins", CrySearchIml::PluginsMenuSmall(), THISBACK(PluginsMenuClicked));
}

// // Populates the menu bar for debugger settings.
void CrySearchForm::DebuggerMenu(Bar& pBar)
{
	// If the modules in the opened process could not be retrieved, we can't display this menu.
	if (this->processLoaded)
	{
		const bool isAttached = mDebugger && mDebugger->IsDebuggerAttached();
		const bool isReadOnly = mMemoryScanner->IsReadOnlyOperationMode();
		
		pBar.Add(!isAttached && !isReadOnly, "Attach", CrySearchIml::DebuggerAttach(), THISBACK(DebuggerAttachMenu));
		pBar.Add(isAttached, "Detach", THISBACK(DebuggerDetachMenu));
	}
}

// Populates the menu bar for window visibility settings.
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

// Populates the help menu bar.
void CrySearchForm::HelpMenu(Bar& pBar)
{
	pBar.Add("About", CrySearchIml::AboutButton(), THISBACK(AboutCrySearch));
}

// // Populates the menu bar for changing properties of address table entries.
void CrySearchForm::ChangeRecordSubMenu(Bar& pBar)
{
	pBar.Add("Description", THISBACK1(AddressListChangeProperty, CRDM_DESCRIPTION));
	pBar.Add(this->mUserAddressList.GetSelectCount() == 1, "Address", THISBACK1(AddressListChangeProperty, CRDM_ADDRESS));
	pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Value", THISBACK1(AddressListChangeProperty, CRDM_VALUE));
	pBar.Add("Type", THISBACK1(AddressListChangeProperty, CRDM_TYPE));
}

// Executed when the user right-clicks an address in the address table.
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
			pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Thaw", CrySearchIml::ThawIconSmall(), THISBACK(ToggleAddressTableFreezeThaw));
		}
		else
		{
			pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode(), "Freeze", CrySearchIml::FreezeAddressSmall(), THISBACK(ToggleAddressTableFreezeThaw));
		}
		
		// Add decimal/hexadecimal toggle button.
		pBar.Add(viewAddressTableValueHex ? "View as decimal" : "View as hexadecimal", THISBACK(ToggleAddressTableValueView)).Check(viewAddressTableValueHex);
		
		const bool canDbg = (mDebugger && mDebugger->IsDebuggerAttached()) && this->mUserAddressList.GetSelectCount() == 1;
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
		pBar.Add("Delete\tDEL", CrySearchIml::DeleteButton(), THISBACK(DeleteUserDefinedAddress));
	}
}

// Populates the menu bar for setting breakpoints.
void CrySearchForm::SetDataBreakpointMenu(Bar& pBar)
{
	pBar.Add("Read", THISBACK(SetDataBreakpointOnRead));
	pBar.Add("Write", THISBACK(SetDataBreakpointOnReadWrite));
	pBar.Add("Execute", THISBACK(SetDataBreakpointOnExecute));
}

// Executed when the user right-clicks a search result.
void CrySearchForm::SearchResultWhenBar(Bar& pBar)
{
	if (this->mScanResults.GetCursor() >= 0 && mMemoryScanner->GetScanResultCount() > 0)
	{
		pBar.Add("Add to address list", CrySearchIml::AddToAddressList(), THISBACK(SearchResultDoubleClicked));
		pBar.Add("View as hexadecimal", THISBACK(ToggleSearchResultViewAs)).Check(GlobalScanParameter->CurrentScanHexValues);
	}
}

// ---------------------------------------------------------------------------------------------

// Checks key presses across all controls. Consider it a global key event function.
void CrySearchForm::CheckKeyPresses()
{
	// If hotkeys are enabled, execute the hotkeys procedure.
	if (SettingsFile::GetInstance()->GetEnableHotkeys())
	{
		this->HotkeysProcedure();
	}
	
	// Reinstate the callback for the next key check.
	SetTimeCallback(100, THISBACK(CheckKeyPresses), HOTKEY_TIMECALLBACK);
}

// Called regularly to update the search results currently visible.
void CrySearchForm::SearchResultListUpdater()
{
	// Refresh the address table ArrayCtrl to force updating of the values.
	this->mScanResults.Refresh();
	
	// Reinstate the callback for the next iteration.
	SetTimeCallback(1000, THISBACK(SearchResultListUpdater), UPDATE_RESULTS_TIMECALLBACK);
}

// Called regularly to update entries currently in the address table.
void CrySearchForm::AddressValuesUpdater()
{
	// If CrySearch is operating in read only mode, nothing may be written to the target process.
	if (mMemoryScanner->IsReadOnlyOperationMode())
	{
		return;
	}
	
	// Handle frozen addresses.
	const int addrTableCount = loadedTable.GetCount();
	for (int i = 0; i < addrTableCount; ++i)
	{
		// If we are currently looking at a frozen entry, we need to write its value there.
		const AddressTableEntry* curEntry = loadedTable[i];
		if (curEntry->Frozen)
		{
			// Read the current values into local variables.
			const int curIntValue = ScanInt(curEntry->Value, NULL, 10);
			const double curDoubleValue = StrDbl(curEntry->Value);

			// Get the correct data size for writing.
			switch (curEntry->ValueType)
			{
				case CRYDATATYPE_BYTE:
					mMemoryScanner->Poke(curEntry->Address, &curIntValue, sizeof(Byte));
					break;
				case CRYDATATYPE_2BYTES:
					mMemoryScanner->Poke(curEntry->Address, &curIntValue, sizeof(short));
					break;
				case CRYDATATYPE_4BYTES:
					mMemoryScanner->Poke(curEntry->Address, &curIntValue, sizeof(int));
					break;
				case CRYDATATYPE_8BYTES:
					{
						const __int64 curLongValue = ScanInt64(curEntry->Value, NULL, 10);
						mMemoryScanner->Poke(curEntry->Address, &curLongValue, sizeof(__int64));
					}
					break;
				case CRYDATATYPE_FLOAT:
					{
						const float fValue = (float)curDoubleValue;
						mMemoryScanner->Poke(curEntry->Address, &fValue, sizeof(float));
					}
					break;
				case CRYDATATYPE_DOUBLE:
					mMemoryScanner->Poke(curEntry->Address, &curDoubleValue, sizeof(double));
					break;
				case CRYDATATYPE_AOB:
					{
						ArrayOfBytes curAobValue = StringToBytes(curEntry->Value);
						mMemoryScanner->PokeB(curEntry->Address, curAobValue);
						curEntry->Size = curAobValue.Size;
					}
					break;
				case CRYDATATYPE_STRING:
					mMemoryScanner->PokeA(curEntry->Address, curEntry->Value);
					break;
				case CRYDATATYPE_WSTRING:
					mMemoryScanner->PokeW(curEntry->Address, curEntry->Value.ToWString());
					break;
			}
		}
	}
	
	// Refresh the address table ArrayCtrl to force the values to update.
	this->mUserAddressList.Refresh();
	
	// Reinstate timer queue callback to ensure timer keeps running.
	SetTimeCallback(SettingsFile::GetInstance()->GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), ADDRESS_TABLE_UPDATE_TIMECALLBACK);
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
			KillTimeCallback(PROCESS_TERMINATION_TIMECALLBACK);
		}
	}
	
	SetTimeCallback(250, THISBACK(CheckProcessTermination), PROCESS_TERMINATION_TIMECALLBACK);
}

// ---------------------------------------------------------------------------------------------

// Handles the removal of items from the address table.
void CrySearchForm::AddressTableRemovalRoutine(const Vector<int>& items)
{
	// Remove breakpoint from data if necessary.
	const int count = items.GetCount();
	for (int i = 0; i < count; ++i)
	{
		if (mDebugger && mDebugger->IsDebuggerAttached())
		{
			mDebugger->RemoveBreakpoint(loadedTable[items[i]]->Address);
		}
	}
	
	// Remove the items from the address table and refresh the control.
	loadedTable.Remove(items);
	this->mUserAddressList.Clear();
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

// Hides or shows the lower window pane.
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
	
	this->mMainSplitter.SetMinPixels(0, 100);
	this->mMainSplitter.SetMinPixels(1, 100);
	this->lowerPaneHidden = !this->lowerPaneHidden;
}

// Adjusts the position of the main window splitter control.
void CrySearchForm::SetMainSplitterPosition()
{
	const Rect r = this->mMainSplitter.GetRect();
	const int total = r.bottom - r.top;
	this->mMainSplitter.SetPos(((total / 2) * 10000 / total) - 600);
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

// Executed when the tab window currently active has changed. This situation needs to be
// handled separately because the imports window needs redrawal.
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
		String windowTitle = this->processLoaded ? Format("%s - (%i) %s", (char*)wndTitle, mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()) : (char*)wndTitle;
		this->Title(SettingsFile::GetInstance()->GetEnableReadOnlyMode() ? Format("%s - (Read-Only)", windowTitle) : windowTitle);
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

// Executes the heap walk dialog.
void CrySearchForm::HeapWalkMenuClicked()
{
	CryHeapWalkDialog* chwd = new CryHeapWalkDialog(CrySearchIml::HeapWalkSmall());
	chwd->Execute();
	delete chwd;
}

// Sets a hardware breakpoint on an address.
void CrySearchForm::SetBreakpointMenuFunction(const HWBP_TYPE type)
{
	const int cursor = this->mUserAddressList.GetCursor();
	HWBP_SIZE size = HWBP_SIZE_4;
	
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

// Sets a read breakpoint on the selected data address (in the address table).
void CrySearchForm::SetDataBreakpointOnRead()
{
	this->SetBreakpointMenuFunction(HWBP_TYPE_READWRITE);
}

// Sets a read/write breakpoint on the selected data address (in the address table).
void CrySearchForm::SetDataBreakpointOnReadWrite()
{
	this->SetBreakpointMenuFunction(HWBP_TYPE_WRITE);
}

// Sets a breakpoint on the selected address.
void CrySearchForm::SetDataBreakpointOnExecute()
{
	this->SetBreakpointMenuFunction(HWBP_TYPE_EXECUTE);
}

// Removes a breakpoint from the selected address.
void CrySearchForm::RemoveBreakpointMenu()
{
	this->mWindowManager.GetDebuggerWindow()->Cleanup();
	mDebugger->RemoveBreakpoint(loadedTable[this->mUserAddressList.GetCursor()]->Address);
}

// Executes operations to brute force PIDs (Process ID's) to find hidden processes.
void CrySearchForm::BruteForcePIDClicked()
{
	CryBruteforcePIDWindow* cbfpidw = new CryBruteforcePIDWindow();
	if (cbfpidw->Execute() == 10)
	{
		// If the dialog result is 10, the user requested to open a brute-forced process.
		this->WhenProcessOpened(cbfpidw->GetSelectedProcess(), true);
	}
	delete cbfpidw;
}

// Executes the plugins window.
void CrySearchForm::PluginsMenuClicked()
{
	CryPluginsWindow* cpw = new CryPluginsWindow();
	cpw->Execute();
	delete cpw;
}

// Opens an address table file to be loaded into memory.
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

// Executed when the user double clicks an address table entry.
void CrySearchForm::UserDefinedEntryWhenDoubleClicked()
{
	const int row = this->mUserAddressList.GetCursor();
	const int column = this->mUserAddressList.GetClickColumn();
	
	if (row >= 0 && loadedTable.GetCount() > 0)
	{
		Vector<int> singleRowInput = { row };
		switch (column)
		{
#ifdef _WIN64
			case 0: // description
				CryChangeRecordDialog(loadedTable, singleRowInput, CRDM_DESCRIPTION).Execute();
				break;
			case 1: // address
				CryChangeRecordDialog(loadedTable, singleRowInput, CRDM_ADDRESS).Execute();
				break;
			case 2: // value
				CryChangeRecordDialog(loadedTable, singleRowInput, mMemoryScanner->IsReadOnlyOperationMode() ? CRDM_DESCRIPTION : CRDM_VALUE).Execute();
				break;
			case 3: // type
				CryChangeRecordDialog(loadedTable, singleRowInput, CRDM_TYPE).Execute();
				break;
#else
			case 0: // description
				CryChangeRecordDialog(loadedTable, singleRowInput, CRDM_DESCRIPTION).Execute();
				break;
			case 1: // address
				CryChangeRecordDialog(loadedTable, singleRowInput, CRDM_ADDRESS).Execute();
				break;
			case 2: // value
				CryChangeRecordDialog(loadedTable, singleRowInput, mMemoryScanner->IsReadOnlyOperationMode() ? CRDM_DESCRIPTION : CRDM_VALUE).Execute();
				break;
			case 3: // type
				CryChangeRecordDialog(loadedTable, singleRowInput, CRDM_TYPE).Execute();
				break;
#endif
		}
	}
}

// Freezes addresses that are thawn and thaws frozen addresses.
void CrySearchForm::ToggleAddressTableFreezeThaw()
{
	loadedTable[this->mUserAddressList.GetCursor()]->Frozen = !loadedTable[this->mUserAddressList.GetCursor()]->Frozen;
}

// Toggles whether entries in the address table are currently shown in hexadecimal format or decimal format.
void CrySearchForm::ToggleAddressTableValueView()
{
	viewAddressTableValueHex = !viewAddressTableValueHex;
}

// Toggles whether the search results are currently shown in hexadecimal format or decimal format.
void CrySearchForm::ToggleSearchResultViewAs()
{
	GlobalScanParameter->CurrentScanHexValues = !GlobalScanParameter->CurrentScanHexValues;
}

// Open a dialog to enable the user to manually add an address to the address table.
void CrySearchForm::ManuallyAddAddressToTable()
{
	CryChangeRecordDialog(loadedTable, Vector<int>(), CRDM_MANUALNEW).Execute();
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

// Change a property of a selected address table entry (address, description, value or type).
void CrySearchForm::AddressListChangeProperty(ChangeRecordDialogMode mode)
{
	const int row = this->mUserAddressList.GetCursor();
	const int totalCount = loadedTable.GetCount();
	if (row >= 0 && totalCount > 0)
	{
		// Get selected rows.
		Vector<int> selectedRows;
		for (int r = 0; r < totalCount; ++r)
		{
			if (this->mUserAddressList.IsSelected(r))
			{
				selectedRows << r;
			}
		}
		
		// Open the record changing dialog corresponding to the selected mode.
		switch (mode)
		{
			case CRDM_DESCRIPTION:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_DESCRIPTION).Execute();
#else
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_DESCRIPTION).Execute();
#endif
				break;
			case CRDM_ADDRESS:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_ADDRESS).Execute();
#else
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_ADDRESS).Execute();
#endif
				break;
			case CRDM_VALUE:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_VALUE).Execute();
#else
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_VALUE).Execute();
#endif
				break;
			case CRDM_TYPE:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_TYPE).Execute();
#else
				CryChangeRecordDialog(loadedTable, selectedRows, CRDM_TYPE).Execute();
#endif
				break;
		}
	}
}

// Saves the currently loaded address table to a file.
void CrySearchForm::SaveFileMenu()
{
	if (!loadedTable.GetFileName().IsEmpty())
	{
		AddressTable::SaveAddressTableToFile(loadedTable, loadedTable.GetFileName());
	}
}

// Execute a save as dialog on the currently loaded address table.
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

// Shows the disassembly window if it is currently hidden, or hides it if it is currently shown.
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

// Deletes a specific address in the address table.
void CrySearchForm::DeleteUserDefinedAddress()
{
	const int totalCount = loadedTable.GetCount();
	if (this->mUserAddressList.GetCursor() >= 0 && totalCount > 0)
	{
		// Get selected rows.
		Vector<int> selectedRows;
		for (int r = 0; r < totalCount; ++r)
		{
			if (this->mUserAddressList.IsSelected(r))
			{
				selectedRows << r;
				
				// Remove breakpoint from data if necessary.
				if (mDebugger && mDebugger->IsDebuggerAttached())
				{
					mDebugger->RemoveBreakpoint(loadedTable[r]->Address);
				}
			}
		}
		
		// Delete all selected rows. We do this in reverse to avoid index problems.
		loadedTable.Remove(selectedRows);
		
		// Refresh the address table user interface.
		this->mUserAddressList.Clear();
		this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	}
}

// Clears the address table.
void CrySearchForm::ClearAddressList()
{
	if (Prompt("I need your confirmation", CtrlImg::exclamation(), "Are you sure you want to clear the address list?", "Yes", "No"))
	{
		// When clearing the list, assurance of all data breakpoints being removed must be made.
		if (mDebugger && mDebugger->IsDebuggerAttached())
		{
			const int count = loadedTable.GetCount();
			for (int i = 0; i < count; ++i)
			{
				mDebugger->RemoveBreakpoint(loadedTable[i]->Address);
			}
		}
		
		// Clear UI and underlying data table structures.
		this->mUserAddressList.Clear();
		loadedTable.Clear();
	}
}

// Occurs when a search result is double clicked.
void CrySearchForm::SearchResultDoubleClicked()
{
	if (this->mScanResults.GetCursor() < 0 || mMemoryScanner->GetScanResultCount() <= 0)
	{
		return;
	}
	
	// If multiple rows are selected, run the add sequence for all of them.
	int rowcount = this->mScanResults.GetCount();
	Vector<int> selectedRows;
	selectedRows.Reserve(this->mScanResults.GetSelectCount());
	for (int r = 0; r < rowcount; ++r)
	{
		if (this->mScanResults.IsSelected(r))
		{
			selectedRows << r;
		}
	}
	
	// Check how many entries may still be added to the address table.
	rowcount = selectedRows.GetCount();
	const int canStillAdd = ADDRESS_TABLE_MAX_SIZE - loadedTable.GetCount();
	if (rowcount > ADDRESS_TABLE_MAX_SIZE || rowcount > canStillAdd)
	{
		Prompt("Input Error", CtrlImg::error(), Format("This insertion violates the address table limit. %i entries can still be added.", canStillAdd), "OK");
		return;
	}
	
	// Walk the selected rows.
	bool failed = false;
	for (int i = 0; i < rowcount; ++i)
	{
		// Retrieve values from virtual columns of the ArrayCtrl.
		const String& value = GetValue(selectedRows[i]);
		CCryDataType toAddToAddressList = GlobalScanParameter->GlobalScanValueType;
	
		// Try to find the address table entry in the existing table.
		const int curRow = loadedTable.Find(CachedAddresses[selectedRows[i]].Address, toAddToAddressList);
		
		// Check whether the address table entry already exists.
		if (curRow != -1)
		{
			failed = true;
			continue;
		}
		
		// Add the entry to the address table.
		const SearchResultCacheEntry& selEntry = CachedAddresses[selectedRows[i]];
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
	}
	
	// If one or more rows were not succesfully added to the address table, throw an error.
	if (failed)
	{
		Prompt("Input Error", CtrlImg::error(), "One or more addresses were not succesfully added to the address table.", "OK");
	}
	
	// Refresh address table in user interface.
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

// Executes a first memory search.
void CrySearchForm::MemorySearch()
{
	// If no process is opened, a scan should not be started.
	if (!this->processLoaded)
	{
		Prompt("Input Error", CtrlImg::error(), "There is no process opened. Please open a process first.", "OK");
		return;
	}
	
	// Open the new scan dialog to allow the user to select options.
	CryNewScanForm* newScan = new CryNewScanForm(true, CrySearchIml::SearchMemoryMenu());
	if (newScan->Execute() != 10)
	{
		delete newScan;
		return;
	}
	
	// Start a new memory scan asynchronously.
	delete newScan;
	this->ClearScanResultsWithoutWarning();

#ifdef _MULTITHREADED
	Thread::Start(THISBACK1(StartMemoryScanReliefGUI, true));
#else
	StartMemoryScanReliefGUI(true);
#endif
}

// Executes a refreshment scan, matching existing search results.
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

// Starts a memory search on a separate thread.
void CrySearchForm::StartMemoryScanReliefGUI(const bool FirstScan)
{
	if (FirstScan)
	{
		mMemoryScanner->FirstScan();
	}
	else
	{
		mMemoryScanner->NextScan();
	}
}

// Executes the open process window.
void CrySearchForm::OpenProcessMenu()
{
	CryProcessEnumeratorForm* cpef = new CryProcessEnumeratorForm(CrySearchIml::AttachToProcessMenu());
	if (cpef->Execute() == 10)
	{
		this->WhenProcessOpened(cpef->GetSelectedProcess(), false);
	}
	
	delete cpef;
}

// Closes the currently opened process.
void CrySearchForm::CloseProcessMenu()
{
	if (this->CloseProcess())
	{
		// Tell the loaded plugins that the currently loaded process has closed.
		mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_PROCESS_CLOSED, NULL);
	}
}

// Routine that is executed on the closure of an opened process.
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
	const int count = loadedTable.GetCount();
	for (int i = 0; i < count; ++i)
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
	KillTimeCallback(ADDRESS_TABLE_UPDATE_TIMECALLBACK);
	
	// Refresh address table for user interface.
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	
	return true;
}

// Exits CrySearch, initiating the cleanup procedure.
void CrySearchForm::ExitApplication()
{
	this->Close();
}

// Executes the settings window.
void CrySearchForm::SettingsButtonClicked()
{
	CrySearchSettingsDialog* cssd = new CrySearchSettingsDialog();
	cssd->Execute();
	delete cssd;
	
	this->LinkHotkeysToActions();
	
	// If the hotkeys are enabled, reinstate the callback for the next poll session.
	if (SettingsFile::GetInstance()->GetEnableHotkeys())
	{
		KillTimeCallback(HOTKEY_TIMECALLBACK);
		SetTimeCallback(100, THISBACK(CheckKeyPresses), HOTKEY_TIMECALLBACK);
	}
}

// Attaches the debugger to the opened process and shows the debugger window.
void CrySearchForm::DebuggerAttachMenu()
{
	mDebugger->Start();
	this->ToggleDebuggerWindow();
}

// Detaches the debugger from the opened process and hides the debugger window.
void CrySearchForm::DebuggerDetachMenu()
{
	mDebugger->Stop();
	this->ToggleDebuggerWindow();
}

// If the debugger threw an internal error, the debugger window should be hidden.
void CrySearchForm::DebugWindowErrorOccured()
{
	this->ToggleDebuggerWindow();
}

// Executes the code generation window.
void CrySearchForm::CodeGenerationButtonClicked()
{
	CryCodeGenerationForm* ccgf = new CryCodeGenerationForm();
	ccgf->Execute();
	delete ccgf;
}

// Executes the memory dissection window.
void CrySearchForm::MemoryDissectionButtonClicked()
{
	CryMemoryDissectionWindow* cmdw = new CryMemoryDissectionWindow(NULL);
	cmdw->Execute();
	delete cmdw;
	
	// New entries may have been added to the address table from the dissection window. Refresh the control to show newly added ones.
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

// Executes the system handle view window.
void CrySearchForm::ViewSystemHandlesButtonClicked()
{
	CrySystemHandleInformationWindow* cshiw = new CrySystemHandleInformationWindow(CrySearchIml::ViewHandlesButton());
	cshiw->Execute();
	delete cshiw;
}

// Executes the PEB (Process Environment Block) window.
void CrySearchForm::ViewPEBButtonClicked()
{
	CryProcessEnvironmentBlockWindow* cpebw = new CryProcessEnvironmentBlockWindow(CrySearchIml::AboutButton());
	cpebw->Execute();
	delete cpebw;
}

// Opens the dialog to allocate a block of memory in the targeted process.
void CrySearchForm::AllocateMemoryButtonClicked()
{
	AllocateMemoryDataStruct dataStruct;
	CryAllocateMemoryWindow* allocWnd = new CryAllocateMemoryWindow(&dataStruct);
	
	if (allocWnd->Execute() != 10)
	{
		delete allocWnd;
		return;
	}
	
	delete allocWnd;
	
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
}

// Opens the dialog to fill a block of memory in the targeted process.
void CrySearchForm::FillMemoryButtonClicked()
{
	FillMemoryDataStruct dataStruct;
	CryFillMemoryWindow* cfmw = new CryFillMemoryWindow(&dataStruct);
	
	// Execute the fill memory window to allow the user to input his choices.
	if (cfmw->Execute() != 10)
	{
		delete cfmw;
		return;
	}
	
	delete cfmw;
	
	bool succeeded = false;
	SIZE_T written = 0;
	
	// Set the limit for the size of a memory block to 128 MB. Otherwise idiots can easily crash CrySearch.
	const unsigned int memorySize = dataStruct.MemorySize;
	if (memorySize <= 134217728)
	{
		// Locally allocate a memory block to write out.
		Byte* const memoryBlock = new Byte[memorySize];
		
		if (dataStruct.Randomize)
		{
			// The user chose random values for the memory block to be filled.
			for (unsigned int i = 0; i < memorySize; i += sizeof(DWORD))
			{
				*(DWORD*)(memoryBlock + i) = Random();
			}
			
			// Write the filled memory block to the targeted process.
			succeeded = WriteProcessMemory(mMemoryScanner->GetHandle(), (void*)dataStruct.Address, memoryBlock, memorySize, &written);
		}
		else
		{
			// The user chose the memory block to be filled with a specific integer value.
			memset(memoryBlock, dataStruct.Value, memorySize);
			
			// Write the filled memory block to the targeted process.
			succeeded = WriteProcessMemory(mMemoryScanner->GetHandle(), (void*)dataStruct.Address, memoryBlock, memorySize, &written);
		}
		
		delete[] memoryBlock;
	}
	else
	{
		// The memory block was bigger than 128 MB.
		Prompt("Input Error", CtrlImg::error(), "The limit for filling blocks is 128 MB.", "OK");
		return;
	}
	
	// Check if the write succeeded. If not, throw an error.
	if (!succeeded || written != memorySize)
	{
		Prompt("Input Error", CtrlImg::error(), "Failed to write the filled memory block to the target process.", "OK");
	}
}

// Shows the threads window if it is not shown yet, or hides if it is currently shown.
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

// Shows the modules window if it is not shown yet, or hides if it is currently shown.
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

// Shows the pe information window if it is not shown yet, or hides if it is currently shown.
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

// Shows the imports window if it is not shown yet, or hides if it is currently shown.
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

// Shows the debugger window if it is not shown yet, or hides if it is currently shown.
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

// In case an exception occured in CrySearch while executing another thread, the window
// execution needs to deferred to the UI thread.
void CrySearchForm::ExecuteCrashHandlerWindow(const String& msg)
{
	volatile bool comp = false;
	PostCallback(THISBACK2(ExecuteCrashHandlerWindowSafe, msg, &comp));
	while (!comp)
	{
		Sleep(25);
	}
}

// Executes the crash handler window on the UI thread.
void CrySearchForm::ExecuteCrashHandlerWindowSafe(const String& msg, volatile bool* const comp)
{
	CryCrashHandlerWindow* cchw = new CryCrashHandlerWindow(msg);
	cchw->Execute();
	delete cchw;
	*comp = true;
}

// Executes the CrySearch about dialog.
void CrySearchForm::AboutCrySearch()
{
	CrySearchAboutDialog().Execute();
}

// Prompts the user to clear the search results.
void CrySearchForm::ClearScanResults()
{
	if (this->mScanResults.GetCount() > 0 && !Prompt("I need your confirmation", CtrlImg::exclamation()
		, "Do you want to keep the current scan results?", "Yes", "No"))
	{
		this->mScanResults.Clear();
		mMemoryScanner->ClearSearchResults();
		this->mSearchResultCount.SetLabel("Search Results: 0");
		this->mToolStrip.Set(THISBACK(ToolStrip));
	}
}

// Clears the search results without prompting the user.
void CrySearchForm::ClearScanResultsWithoutWarning()
{
	this->mScanResults.Clear();
	mMemoryScanner->ClearSearchResults();
	
	this->mSearchResultCount.SetLabel("Search Results: 0");
	this->mToolStrip.Set(THISBACK(ToolStrip));
}

// Executed when opening of a process failed.
void CrySearchForm::ProcessOpenFailedState(const bool bruteForce)
{
	// We want to reopen the process selection window only if this error state was not
	// produced from a brute-force attempt.
	if (!bruteForce)
	{
		PostCallback(THISBACK(OpenProcessMenu));
	}
}

// Initializes user interface components for a newly opened process.
bool CrySearchForm::InitializeProcessUI(const bool bruteForce)
{
#ifndef _WIN64
	// Check the architecture of the loaded process. Under x64, processes can cause trouble.
	if (mMemoryScanner->IsX86Process())
	{
		// Load modules and threads first, other components depend on them.
		this->mWindowManager.GetModuleWindow()->Initialize();
		this->mWindowManager.GetThreadWindow()->Initialize();

		// If we didn't succeed in retrieving the module list, we cannot do any of the following.
		if (mModuleManager->GetModuleCount())
		{
			// Instantiate PE and debugger classes.
			mPeInstance = new PortableExecutable32();
			mDebugger = new CryDebugger32();
			
			this->mWindowManager.GetPEWindow()->Initialize();
			this->mWindowManager.GetImportsWindow()->Initialize();
			this->mWindowManager.GetDisasmWindow()->Initialize();
			this->mWindowManager.GetDebuggerWindow()->Initialize();
		}
	}
	else
	{
		const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
		Prompt("Load Error", CtrlImg::error(), Format("Failed to open the selected process because it is 64-bit. Use %s x64 to open it instead.", (char*)appname), "OK");
		mMemoryScanner->CloseProcess();
		this->ProcessOpenFailedState(bruteForce);
		return false;
	}
#else
	this->mWindowManager.GetModuleWindow()->Initialize();
	this->mWindowManager.GetThreadWindow()->Initialize();
	
	// If we didn't succeed in retrieving the module list, we cannot do any of the following.
	if (mModuleManager->GetModuleCount())
	{
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
		this->mWindowManager.GetDebuggerWindow()->Initialize();
	}
#endif
	// Still here so the process loaded succesfully. Update user interface and prepare tabs.
	this->processLoaded = true;
	this->mToolStrip.Set(THISBACK(ToolStrip));

	// Set timer callback that runs the address list update sequence.
	SetTimeCallback(SettingsFile::GetInstance()->GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), ADDRESS_TABLE_UPDATE_TIMECALLBACK);
	
	// Succesfully initialized user interface.
	return true;
}

void CrySearchForm::WhenProcessOpened(Win32ProcessInformation* pProc, const bool bruteForce)
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
				if (!this->InitializeProcessUI(bruteForce))
				{
					return;
				}
				
				// If the window title should be randomized, the opened process indicator should be added to the window itself.
				if (this->wndTitleRandomized)
				{
					this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
				}
				else
				{
					DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
					String windowTitle = Format("%s - (%i) %s", (char*)wndTitle, pProc->ProcessId, mMemoryScanner->GetProcessName());
					this->Title(SettingsFile::GetInstance()->GetEnableReadOnlyMode() ? Format("%s - (Read-Only)", windowTitle) : windowTitle);
					this->mOpenedProcess.SetLabel("");
				}
				
				this->mMenuStrip.Set(THISBACK(MainMenu));
				
				this->mTabbedDataWindows.Add(this->mWindowManager.GetPEWindow()->SizePos(), "General");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetDisasmWindow()->SizePos(), "Disassembly");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetImportsWindow()->SizePos(), "Imports");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetThreadWindow()->SizePos(), "Threads");
				this->mTabbedDataWindows.Add(this->mWindowManager.GetModuleWindow()->SizePos(), "Modules");
				
				this->ProcessTerminated = false;
				SetTimeCallback(250, THISBACK(CheckProcessTermination), PROCESS_TERMINATION_TIMECALLBACK);
			}
			else
			{
				// CreateProcess succeeded, but the process is not started succesfully. For example: write.exe starts wordpad.exe and then terminates.
				Prompt("Load Error", CtrlImg::error(), "The process started succesfully but terminated before initialization. Possibly the process started another process and terminated.", "OK");
				mMemoryScanner->CloseProcess();
				this->ProcessOpenFailedState(bruteForce);
			}
		}
		else
		{
			// CreateProcess failed, no process is loaded.
			Prompt("Load Error", CtrlImg::error(), "Failed to create the process.", "OK");
			this->ProcessOpenFailedState(bruteForce);
		}
	}
	else
	{
		// Use process ID to open an existing process.
		if (mMemoryScanner->InitializeExistingProcess(pProc->ProcessId, NULL, SettingsFile::GetInstance()->GetEnableReadOnlyMode()))
		{
			if (!this->InitializeProcessUI(bruteForce))
			{
				return;
			}
			
			// If the window title should be randomized, the opened process indicator should be added to the window itself.
			if (this->wndTitleRandomized)
			{
				this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
			}
			else
			{
				DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
				String windowTitle = Format("%s - (%i) %s", (char*)wndTitle, pProc->ProcessId, mMemoryScanner->GetProcessName());
				this->Title(SettingsFile::GetInstance()->GetEnableReadOnlyMode() ? Format("%s - (Read-Only)", windowTitle) : windowTitle);
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
			SetTimeCallback(250, THISBACK(CheckProcessTermination), PROCESS_TERMINATION_TIMECALLBACK);
		}
	}
	
	// Update toolbars in different lower-pane windows to enforce read-only mode.
	this->mWindowManager.UpdateLowerPaneWindowsToolbars();
	
	// Resolve relative addresses. An address table may be loaded before the process was loaded, hence the entries weren't yet resolved.
	AddressTable::ResolveRelativeEntries(loadedTable);
	
	// Tell the loaded plugins that a process has loaded. The PID is passed into the plugin.
	mPluginSystem->SendGlobalPluginEvent(CRYPLUGINEVENT_PROCESS_OPENED, (void*)pProc->ProcessId);
}

// Executed asynchronously when the memory scanner has started a scan.
void CrySearchForm::ScannerScanStarted(int threadCount)
{
	PostCallback(THISBACK1(ScannerScanStartedThreadSafe, threadCount));
}

// Executed synchronously when the memory scanner has started a scan. This function may alter UI components.
void CrySearchForm::ScannerScanStartedThreadSafe(int threadCount)
{
	// Update the user interface to make a new scan visible.
	this->mToolStrip.Set(THISBACK(ToolStrip));
	this->mScanningProgress.Show();
	this->mScanningProgress.Set(0, threadCount);
	
	// Schedule a callback to periodically check for memory scanner completion.
	SetTimeCallback(10, THISBACK(ScannerPeekCompletion), MEMORY_SCANNER_COMPLETION_TIMECALLBACK);
}

// Executed asynchronously when the memory scanner updates its status.
void CrySearchForm::ScannerUserInterfaceUpdate(int threadCount)
{
	PostCallback(THISBACK1(ScannerUserInterfaceUpdateThreadSafe, threadCount));
}

// Executed synchronously when the memory scanner updates its status. This function may alter UI components.
void CrySearchForm::ScannerUserInterfaceUpdateThreadSafe(int threadCount)
{
	this->mScanningProgress.Set(threadCount);
}

// Executed asynchronously when an error occured in the memory scanner.
void CrySearchForm::ScannerErrorOccured(MemoryScannerError error)
{
	PostCallback(THISBACK1(ScannerErrorOccuredThreadSafe, error));
}

// Executed synchronously when an error occured in the memory scanner. This function may alter UI components.
void CrySearchForm::ScannerErrorOccuredThreadSafe(MemoryScannerError error)
{
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	switch (error)
	{
		case OPENPROCESSFAILED:
			// Kill timer callback, otherwise two error messages will pop up.
			KillTimeCallback(PROCESS_TERMINATION_TIMECALLBACK);
			
			Prompt("Process Error", CtrlImg::error(), Format("Could not open the selected process. The process is either protected or 64-bit."\
				" To open a protected process, try running %s as Administrator.", (char*)appname), "OK");
			PostCallback(THISBACK(OpenProcessMenu));
			break;
		case PROCESSWASTERMINATED:
			// Kill timer callback, otherwise the stack will overflow.
			KillTimeCallback(PROCESS_TERMINATION_TIMECALLBACK);
			
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

	// In case of an error, erase the content of the user interface indicators.
	this->mScanResults.Clear();
	this->mSearchResultCount.SetLabel("Search Results: 0");
}

// Peeks whether the memory scanner has completed its work or not.
void CrySearchForm::ScannerPeekCompletion()
{
	// Peek the memory scanner to see if it has completed its work yet.
	if (mMemoryScanner->GetIsWorkCompleted())
	{
		// The memory scan has completed. Tell the memory scanner to clean up its resources.
		mMemoryScanner->SetWorkCompleted();
		
		// Update the result counter label to show the amount of search results the scan resulted in.
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
		
		// Hide the scan progress indicator.
		this->mScanningProgress.Hide();
		this->mToolStrip.Set(THISBACK(ToolStrip));
		
		// Cheat Engine has this nice beep when a scan completes, why shouldn't I? :)
		BeepExclamation();
	}
	else
	{
		// Schedule the next callback to periodically check for memory scanner completion.
		SetTimeCallback(10, THISBACK(ScannerPeekCompletion), MEMORY_SCANNER_COMPLETION_TIMECALLBACK);
	}
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
	// Check whether the tag page is already opened.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, wndText);
	if (i >= 0)
	{
		// Set it to be active.
		this->mTabbedDataWindows.Set(i);
		return true;
	}
	
	return false;
}