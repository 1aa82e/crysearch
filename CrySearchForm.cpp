// Nessecary dialog includes and IML provider for imaging.
#include "CrySearchForm.h"
#include "CrySettingsDialog.h"
#include "CrySearchAboutDialog.h"
#include "CryProcessEnumeratorForm.h"
#include "CryNewScanForm.h"
#include "CryAllocateMemoryWindow.h"
#include "CryCodeGenerationForm.h"
#include "CryProcessEnvironmentBlockWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// Global source IML file declaration. Imaging in the GUI depends on this.
#define IMAGECLASS CrySearchIml
#define IMAGEFILE "CrySearch.iml"
#include <Draw/iml_source.h>

// Extern declaration of global variables.
MemoryScanner* mMemoryScanner;
AddressTable loadedTable;
SettingsFile GlobalSettingsInstance;
bool viewAddressTableValueHex;

// Global PE methodic class instance, nessecary for over half of the application.
PortableExecutable* mPeInstance;

// Global Debugger class instance, necessary for debugging the remote process.
CryDebugger* mDebugger;

// Stored process PE information.
Win32PEInformation LoadedProcessPEInformation;

String GetAddress(const int index)
{
#ifdef _WIN64
	return Format("%llX", CachedAddresses[index]);
#else
	return Format("%lX", CachedAddresses[index]);
#endif
}

// Virtual array control row accessors.
String GetValue(const int index)
{
	return CachedValues[index].ToString();
}

String GetAddressTableDescription(const AddressTable& instance, const int index)
{
	return instance[index]->Description;
}

String GetAddressTableAddress(const AddressTable& instance, const int index)
{
#ifdef _WIN64
	return Format("%llX", instance[index]->Address);
#else
	return Format("%lX", instance[index]->Address);
#endif
}

String GetAddressTableValue(const AddressTable& instance, const int index)
{
	const AddressTableEntry* entry = instance[index];
	if (entry->ValueType != "String" && entry->ValueType != "Array of Bytes" && entry->ValueType != "WString")
	{
#ifdef _WIN64
		return viewAddressTableValueHex ? Format("%llX", ScanInt64(instance[index]->Value, NULL, 10)) : instance[index]->Value;
#else
		return viewAddressTableValueHex ? Format("%lX", ScanInt(instance[index]->Value, NULL, 10)) : instance[index]->Value;
#endif		
	}
	else
	{
		return instance[index]->Value;
	}
}

String GetAddressTableValueType(const AddressTable& instance, const int index)
{
	return instance[index]->ValueType;
}

// global function to reload default settings whenever the settings file is not readable or not found.
void ReloadDefaultSettings()
{
	GlobalSettingsInstance.SetFastScanByDefault();
	GlobalSettingsInstance.SetScanWritableMemory();
	GlobalSettingsInstance.SetScanExecutableMemory();
	GlobalSettingsInstance.SetScanMemImage();
	GlobalSettingsInstance.SetScanMemPrivate();
	GlobalSettingsInstance.SetScanMemImage();
	GlobalSettingsInstance.SetScanThreadPriority();
	GlobalSettingsInstance.SetOpenProcessRoutine();
	GlobalSettingsInstance.SetAddressTableUpdateInterval();
	GlobalSettingsInstance.SetStackSnapshotLimit();
	GlobalSettingsInstance.Save();
}

void CrySearchForm::AddressValuesUpdater()
{
	// If the address list is empty, don't execute this function at all. Just reset the callback.
	if (this->mUserAddressList.GetCount() <= 0)
	{
		SetTimeCallback(GlobalSettingsInstance.GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
		return;
	}
	
	// Handle frozen addresses
	for (int i = 0; i < loadedTable.GetCount(); i++)
	{
		const AddressTableEntry* curEntry = loadedTable[i];
		if (curEntry->Frozen)
		{
			if (curEntry->ValueType == "Byte")
			{
				mMemoryScanner->Poke<Byte>(curEntry->Address, (Byte)ScanInt(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == "2 Bytes")
			{
				mMemoryScanner->Poke<short>(curEntry->Address, (short)ScanInt(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == "4 Bytes")
			{
				mMemoryScanner->Poke<int>(curEntry->Address, ScanInt(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == "8 Bytes")
			{
				mMemoryScanner->Poke<__int64>(curEntry->Address, ScanInt64(curEntry->Value, NULL, 10));
			}
			else if (curEntry->ValueType == "Float")
			{
				mMemoryScanner->Poke<float>(curEntry->Address, (float)StrDbl(curEntry->Value));
			}
			else if (curEntry->ValueType == "Double")
			{
				mMemoryScanner->Poke<double>(curEntry->Address, StrDbl(curEntry->Value));
			}
			else if (curEntry->ValueType == "Array of Bytes")
			{
				ArrayOfBytes aob = StringToBytes(curEntry->Value);
				mMemoryScanner->Poke(curEntry->Address, aob);
				delete[] aob.Data;
				
				curEntry->Size = aob.Size;
			}
			else if (curEntry->ValueType == "String")
			{
				mMemoryScanner->Poke<String>(curEntry->Address, curEntry->Value);
			}
			else if (curEntry->ValueType == "WString")
			{
				mMemoryScanner->Poke<WString>(curEntry->Address, curEntry->Value.ToWString());
			}
		}
	}
	
	// Get range of visible items in ArrayCtrl using CrySearchArrayCtrl function.
	Tuple2<int, int> addressTableRange = this->mUserAddressList.GetVisibleRange();
	
	if (addressTableRange.a >= 0 && addressTableRange.b < loadedTable.GetCount())
	{
		for (int start = addressTableRange.a; start <= addressTableRange.b; start++)
		{
			if (loadedTable[start]->ValueType == "Byte")
			{
				Byte value;
				if (mMemoryScanner->Peek<Byte>(loadedTable[start]->Address, 0, &value))
				{
					loadedTable[start]->Value = IntStr(value);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "2 Bytes")
			{
				short value;
				if (mMemoryScanner->Peek<short>(loadedTable[start]->Address, 0, &value))
				{
					loadedTable[start]->Value = IntStr(value);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "4 Bytes")
			{
				int value;
				if (mMemoryScanner->Peek<int>(loadedTable[start]->Address, 0, &value))
				{
					loadedTable[start]->Value = IntStr(value);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "8 Bytes")
			{
				__int64 value;
				if (mMemoryScanner->Peek<__int64>(loadedTable[start]->Address, 0, &value))
				{
					loadedTable[start]->Value = IntStr64(value);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "Float")
			{
				float value;
				if (mMemoryScanner->Peek<float>(loadedTable[start]->Address, 0, &value))
				{
					loadedTable[start]->Value = DblStr(value);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "Double")
			{
				double value;
				if (mMemoryScanner->Peek<double>(loadedTable[start]->Address, 0, &value))
				{
					loadedTable[start]->Value = DblStr(value);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "Array of Bytes")
			{
				ArrayOfBytes value;
				if (mMemoryScanner->Peek<ArrayOfBytes>(loadedTable[start]->Address, loadedTable[start]->Size, &value))
				{
					loadedTable[start]->Value = BytesToString(value.Data, value.Size);
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			
				delete[] value.Data;
			}
			else if (loadedTable[start]->ValueType == "String")
			{
				String value;
				if (mMemoryScanner->Peek<String>(loadedTable[start]->Address, loadedTable[start]->Size, &value))
				{
					loadedTable[start]->Value = value;
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
			else if (loadedTable[start]->ValueType == "WString")
			{
				WString value;
				if (mMemoryScanner->Peek<WString>(loadedTable[start]->Address, loadedTable[start]->Size, &value))
				{
					loadedTable[start]->Value = value.ToString();
				}
				else
				{
					loadedTable[start]->Value = "???";
				}
			}
		}
	}
	
	// Refresh ArrayCtrl to display results right away.
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	
	// Reinstate timer queue callback to ensure timer keeps running.
	SetTimeCallback(GlobalSettingsInstance.GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
}

void CrySearchForm::CheckKeyPresses()
{
	const unsigned int count = GlobalSettingsInstance.GetHotkeyCount();
	
	if (count)
	{
		// Iterate saved hotkeys and configure parameters for its configured actions.
		for (unsigned int i = 0; i < count; ++i)
		{
			const CrySearchHotKey& curKey = GlobalSettingsInstance.GetHotkey(i);
			
			// Check if the configured key is currently pressed.
			if (GetAsyncKeyState(curKey.Key) & 1)
			{
				if (!mMemoryScanner->IsScanRunning() && ScanResultCount > 0)
				{
					if (curKey.Description == "Refresh search results, changed value")
					{
						GlobalScanParameter->GlobalScanType = SCANTYPE_CHANGED;
						curKey.Action(false);
					}
					else if (curKey.Description == "Refresh search results, unchanged value")
					{
						GlobalScanParameter->GlobalScanType = SCANTYPE_UNCHANGED;
						curKey.Action(false);
					}
					else if (curKey.Description == "Refresh search results, increased value")
					{
						GlobalScanParameter->GlobalScanType = SCANTYPE_INCREASED;
						curKey.Action(false);
					}
					else if (curKey.Description == "Refresh search results, decreased value")
					{
						GlobalScanParameter->GlobalScanType = SCANTYPE_DECREASED;
						curKey.Action(false);
					}
				}
			}
		}
	}
	
	// Reinstate the callback for the next poll session.
	SetTimeCallback(100, THISBACK(CheckKeyPresses), 20);
}

// This callback checks whether the process is still running, if one is opened.
// If the opened process terminated somehow, CrySearch will close it internally.
void CrySearchForm::CheckProcessTermination()
{
	if (mMemoryScanner->GetProcessId() > 0)
	{
		DWORD exitCode;
		GetExitCodeProcess(mMemoryScanner->GetHandle(), &exitCode);
		if (exitCode != STILL_ACTIVE)
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
	for (unsigned int i = 0; i < GlobalSettingsInstance.GetHotkeyCount(); i++)
	{
		/*if (GlobalSettingsInstance.GetHotkey(i).Description == "Refresh search results, changed value")
		{
			GlobalSettingsInstance.GetHotkey(i).Action = THISBACK(StartMemoryScanReliefGUI);
		}
		else if (GlobalSettingsInstance.GetHotkey(i).Description == "Refresh search results, unchanged value")
		{
			GlobalSettingsInstance.GetHotkey(i).Action = THISBACK(StartMemoryScanReliefGUI);
		}
		else if (GlobalSettingsInstance.GetHotkey(i).Description == "Refresh search results, increased value")
		{
			GlobalSettingsInstance.GetHotkey(i).Action = THISBACK(StartMemoryScanReliefGUI);
		}
		else if (GlobalSettingsInstance.GetHotkey(i).Description == "Refresh search results, decreased value")
		{
			GlobalSettingsInstance.GetHotkey(i).Action = THISBACK(StartMemoryScanReliefGUI);
		}*/
		
		GlobalSettingsInstance.GetHotkey(i).Action = THISBACK(StartMemoryScanReliefGUI);
	}
}

// If CrySearch was opened using a file association, open the file straight away.
// If CrySearch was opened regularly, pass NULL as parameter.
CrySearchForm::CrySearchForm(const char* fn)
{
	this->processLoaded = false;
	this->wndTitleRandomized = false;
	
	this->Title("CrySearch Memory Scanner").Icon(CrySearchIml::CrySearch()).Sizeable().Zoomable().SetRect(0, 0, 800, 600);
	this->SetMinSize(Size(640, 480));
	
	this->AddFrame(mMenuStrip);
	this->mMenuStrip.Set(THISBACK(MainMenu));
	
	this->AddFrame(mToolStrip);
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	this->mScanResults.AddRowNumColumn("Address").SetConvert(Single<IndexBasedValueConvert<GetAddress>>());
	this->mScanResults.AddRowNumColumn("Value").SetConvert(Single<IndexBasedValueConvert<GetValue>>());
	this->mScanResults.WhenLeftDouble = THISBACK(SearchResultDoubleClicked);
	this->mScanResults.WhenBar = THISBACK(SearchResultWhenBar);
	
	this->mUserAddressList.AddRowNumColumn("Description").SetConvert(Single<AddressTableValueConvert<GetAddressTableDescription>>());
	this->mUserAddressList.AddRowNumColumn("Address").SetConvert(Single<AddressTableValueConvert<GetAddressTableAddress>>());
	this->mUserAddressList.AddRowNumColumn("Value").SetConvert(Single<AddressTableValueConvert<GetAddressTableValue>>());
	this->mUserAddressList.AddRowNumColumn("Type").SetConvert(Single<AddressTableValueConvert<GetAddressTableValueType>>());
	this->mUserAddressList.WhenBar = THISBACK(UserDefinedEntryWhenBar);
	this->mUserAddressList.WhenLeftDouble = THISBACK(UserDefinedEntryWhenDoubleClicked);

	this->mSearchResultsPanel
		<< this->mSearchResultCount.SetLabel("Search Results: 0").HSizePosZ(5, 5).TopPos(5, 20)
		<< this->mScanningProgress.RightPos(5, 120).TopPos(5, 20)
		<< this->mScanResults.MultiSelect(false).HSizePosZ(5, 5).VSizePosZ(30, 0)
	;
	
	this->mScanningProgress.Hide();
	
	*this
		<< this->mMainSplitter.Vert(this->mInputScanSplitter.Horz(this->mSearchResultsPanel, this->mUserAddressList.SizePos())
			, this->mTabbedDataWindows.SizePos())
	;
	
	this->mMainSplitter.SetPos(3750);
	this->mMainSplitter.SetMinPixels(0, 100);
	this->mMainSplitter.SetMinPixels(1, 100);
	this->mInputScanSplitter.SetMinPixels(0, 300);
	this->mInputScanSplitter.SetMinPixels(1, 250);
	
	// If settings configuration file is not found, create a new one using default settings.
	if (!ConfigFileExists() || !GlobalSettingsInstance.Initialize())
	{
		//Prompt("Settings Error", CtrlImg::exclamation(), "The settings file was not found or corrupt, and has been overwritten with the defaults. If this is your first run, you can ignore this warning.", "OK");
		ReloadDefaultSettings();
	}
	
	// Initiate the memory scanner class, the most important part of CrySearch.
	mMemoryScanner = MemoryScanner::GetInstance();
	mMemoryScanner->ErrorOccured = THISBACK(ScannerErrorOccured);
	mMemoryScanner->ScanCompleted = THISBACK(ScannerCompletedScan);
	mMemoryScanner->UpdateScanningProgress = THISBACK(ScannerUserInterfaceUpdate);
	mMemoryScanner->ScanStarted = THISBACK(ScannerScanStarted);
	
	// Set timer that runs to keep the UI address table updated.
	SetTimeCallback(GlobalSettingsInstance.GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
	
	// Set timer that runs keeping track of hotkeys.
	SetTimeCallback(100, THISBACK(CheckKeyPresses), 20);
	
	// Assign proper callback functions to configured hotkeys.
	this->LinkHotkeysToActions();
	
	// Wind up UI debugger error event. When attaching fails, the debug window must be closed at once.
	this->mDbgWindow.DebugErrorOccured = THISBACK(DebugWindowErrorOccured);
	
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
	
	if (this->processLoaded)
	{
		pBar.Add("Tools", THISBACK(ToolsMenu));
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
	pBar.Add("Save File", CrySearchIml::SaveFile(), THISBACK(SaveFileMenu));
	
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
		pBar.Add("Allocate Memory", CrySearchIml::CrySearch(), THISBACK(AllocateMemoryButtonClicked));
		pBar.Separator();
		pBar.Add((this->mUserAddressList.GetCount() > 0), "Code Generation", CrySearchIml::CodeGenerationButton(), THISBACK(CodeGenerationButtonClicked));
	}
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
		pBar.Separator();
		
		if (loadedTable[row]->Frozen)
		{
			pBar.Add("Thaw", CrySearchIml::ThawIconSmall(), THISBACK(ToggleAddressTableFreezeThaw));
		}
		else
		{
			pBar.Add("Freeze", CrySearchIml::FreezeAddressSmall(), THISBACK(ToggleAddressTableFreezeThaw));
		}
		
		if (viewAddressTableValueHex)
		{
			pBar.Add("View as decimal", THISBACK(ToggleAddressTableValueView)).Check(true);
		}
		else
		{
			pBar.Add("View as hexadecimal", THISBACK(ToggleAddressTableValueView)).Check(false);
		}
		
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

// Toggles CrySearch's main window to be always on top or not.
void CrySearchForm::ToggleAlwaysOnTop()
{
	this->TopMost(!this->IsTopMost());
}

// Randomizes the window title and sets CrySearch to use menubar label to display the opened process.
void CrySearchForm::RandomizeWindowTitle()
{
	if (this->wndTitleRandomized)
	{
		if (this->processLoaded)
		{
			this->Title(Format("CrySearch Memory Scanner - (%i) %s", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
		}
		else
		{
			this->Title("CrySearch Memory Scanner");
		}

		this->mOpenedProcess.SetLabel("");
	}
	else
	{
		this->Title(GenerateRandomWindowTitle());
		
		// Set the label in the menu bar to be utilized.
		if (this->processLoaded)
		{
			this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
		}
		else
		{
			this->mOpenedProcess.SetLabel("");
		}
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
	if (this->mScanResults.GetCursor() >= 0 && ScanResultCount > 0)
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
	mDebugger->RemoveBreakpoint(loadedTable[this->mUserAddressList.GetCursor()]->Address);
}

void CrySearchForm::OpenFileMenu()
{
	FileSel* fs = new FileSel();
	fs->Types("CrySearch Address Tables\t*.csat\nCheatengine Cheat Tables\t*.ct");
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
			if (filename.EndsWith(".ct") || filename.EndsWith(".CT"))
			{
				// Cheat table, cannot yet be opened.
				PromptOK("Cheat tables cannot yet be opened. Not implemented.");
			}
			else
			{
				AddressTable::CreateAddressTableFromFile(loadedTable, filename);	
				this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
			}
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
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_DESCRIPTION).Execute();				
				break;
			case 1: // address
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_ADDRESS).Execute();
				break;
			case 2: // value
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_VALUE).Execute();
				break;
			case 3: // type
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_TYPE).Execute();
				break;
#else
			case 0: // description
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_DESCRIPTION).Execute();				
				break;
			case 1: // address
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_ADDRESS).Execute();
				break;
			case 2: // value
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_VALUE).Execute();
				break;
			case 3: // type
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_TYPE).Execute();
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
	CryChangeRecordDialog(loadedTable, 0, "4 Bytes", CDRM_MANUALNEW).Execute();
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
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_DESCRIPTION).Execute();
#else
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_DESCRIPTION).Execute();
#endif
				break;
			case CRDM_ADDRESS:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_ADDRESS).Execute();
#else
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_ADDRESS).Execute();
#endif
				break;
			case CRDM_VALUE:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_VALUE).Execute();
#else
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_VALUE).Execute();
#endif
				break;
			case CRDM_TYPE:
#ifdef _WIN64
				CryChangeRecordDialog(loadedTable, ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_TYPE).Execute();
#else
				CryChangeRecordDialog(loadedTable, ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
					, GetAddressTableValueType(loadedTable, row), CRDM_TYPE).Execute();
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
	FileSel* fs = new FileSel();
	fs->Types("CrySearch Address Tables\t*.csat");
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
	if (i >= 0)
	{
		this->mDisasmWindow.ClearList();
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	this->mDisasmWindow.Initialize();
	this->mTabbedDataWindows.Add(this->mDisasmWindow.SizePos(), "Disassembly");
	this->mTabbedDataWindows.Set(this->mDisasmWindow);
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
		loadedTable.Remove(ScanInt64(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
			, GetAddressTableValueType(loadedTable, row));
#else
		loadedTable.Remove(ScanInt(GetAddressTableAddress(loadedTable, row).ToString(), NULL, 16)
			, GetAddressTableValueType(loadedTable, row));
#endif
		this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
	}
}

void CrySearchForm::ClearAddressList()
{
	if (Prompt("I need your confirmation", CtrlImg::exclamation(), "Are you sure you want to clear the address list?", "Yes", "No"))
	{
		// When clearing the list, assurance of all data breakpoints being removed must be made.
		for (int i = 0; i < loadedTable.GetCount(); i++)
		{
			mDebugger->RemoveBreakpoint(loadedTable[i]->Address);
		}
		
		// Clear UI and underlying data table structures.
		this->mUserAddressList.Clear();
		loadedTable.Clear();
	}
}

void CrySearchForm::SearchResultDoubleClicked()
{
	const int cursor = this->mScanResults.GetCursor();
	if (cursor < 0 || ScanResultCount <= 0)
	{
		return;
	}

	// Retrieve values from virtual columns of the ArrayCtrl.
	const String& addr = GetAddress(cursor);
	const String& value = GetValue(cursor);
	
	String toAddToAddressList;
	
	switch (GlobalScanParameter->GlobalScanValueType)
	{
		case VALUETYPE_BYTE:
			toAddToAddressList = "Byte";
			break;
		case VALUETYPE_2BYTE:
			toAddToAddressList = "2 Bytes";
			break;
		case VALUETYPE_4BYTE:
			toAddToAddressList = "4 Bytes";
			break;
		case VALUETYPE_8BYTE:
			toAddToAddressList = "8 Bytes";
			break;
		case VALUETYPE_FLOAT:
			toAddToAddressList = "Float";
			break;
		case VALUETYPE_DOUBLE:
			toAddToAddressList = "Double";
			break;
		case VALUETYPE_STRING:
			toAddToAddressList = "String";
			break;
		case VALUETYPE_WSTRING:
			toAddToAddressList = "WString";
			break;
		case VALUETYPE_AOB:
			toAddToAddressList = "Array of Bytes";
			break;
	}
	
#ifdef _WIN64
	const int curRow = loadedTable.Find(ScanInt64(addr, NULL, 16), toAddToAddressList);
#else
	const int curRow = loadedTable.Find(ScanInt(addr, NULL, 16), toAddToAddressList);
#endif
	
	if (curRow != -1)
	{
		Prompt("Input Error", CtrlImg::error(), "The selected address is already added to the table.", "OK");
		return;
	}
	
	if (!this->mScanResults.IsCursor())
	{
		return;
	}

#ifdef _WIN64
	const AddressTableEntry* newEntry = loadedTable.Add(STRING_EMPTY, ScanInt64(addr, NULL, 16), toAddToAddressList);
#else
	const AddressTableEntry* newEntry = loadedTable.Add(STRING_EMPTY, ScanInt(addr, NULL, 16), toAddToAddressList);
#endif
	
	if (toAddToAddressList == "Array of Bytes")
	{
		// Retrieve size of byte array
		int dataIndex = 0;
		for (int c = 0; c <= value.GetLength(); c++)
		{
			if (value[c] == 0x20 || value[c] == 0x0) // scan for space/null character in string
			{
				++dataIndex;
			}
		}
	
		newEntry->Size = dataIndex;
	}
	else if (toAddToAddressList == "String" || toAddToAddressList == "WString")
	{
		newEntry->Size = value.GetLength();
	}
	
	// If there is no process loaded, set the value to invalid.
	if (!mMemoryScanner->GetProcessId())
	{
		newEntry->Value = "???";
	}
	
	this->mUserAddressList.SetVirtualCount(loadedTable.GetCount());
}

void CrySearchForm::MemorySearch()
{
	if (!this->processLoaded)
	{
		Prompt("Input Error", CtrlImg::error(), "There is no process opened. Please open a process first.", "OK");
		return;
	}
	
	CryNewScanForm* newScan = new CryNewScanForm(true);
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
	
	CryNewScanForm newScan(false);
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
	CryProcessEnumeratorForm* cpef = new CryProcessEnumeratorForm();
	cpef->ProcessOpened = THISBACK(WhenProcessOpened);
	cpef->Execute();
	delete cpef;
}

void CrySearchForm::ReopenProcessMenu()
{
	this->OpenProcessMenu();
}

void CrySearchForm::CloseProcessMenu()
{
	this->CloseProcess();
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
		this->Title("CrySearch Memory Scanner");
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
	this->mPEWindow.ClearList();
	this->mThreadList.ClearList();
	this->mModuleList.ClearList();
	this->mDisasmWindow.ClearList();
	this->mDbgWindow.Cleanup();
	
	this->mTabbedDataWindows.Reset();
	
	// Kill running timers.
	KillTimeCallback(10);
	
	// Clean process name inside address table.
	loadedTable.ClearProcessName();
	
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
	if (GlobalSettingsInstance.GetEnableHotkeys())
	{
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

void CrySearchForm::ViewPEBButtonClicked()
{
	CryProcessEnvironmentBlockWindow* cpebw = new CryProcessEnvironmentBlockWindow();
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
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	this->mThreadList.Initialize();
	this->mTabbedDataWindows.Add(this->mThreadList.SizePos(), "Threads");
	this->mTabbedDataWindows.Set(this->mThreadList);
}

void CrySearchForm::ViewModulesButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Modules");
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	this->mModuleList.Initialize();
	this->mTabbedDataWindows.Add(this->mModuleList.SizePos(), "Modules");
	this->mTabbedDataWindows.Set(this->mModuleList);
}

void CrySearchForm::ViewGeneralButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "General");
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	this->mPEWindow.Initialize();
	this->mTabbedDataWindows.Add(this->mPEWindow.SizePos(), "General");
	this->mTabbedDataWindows.Set(this->mPEWindow);
}

void CrySearchForm::ViewImportsButtonClicked()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Imports");
	if (i >= 0)
	{
		LoadedProcessPEInformation.ClearImportTable();
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	this->mImportsWindow.Initialize();
	this->mTabbedDataWindows.Add(this->mImportsWindow.SizePos(), "Imports");
	this->mTabbedDataWindows.Set(this->mImportsWindow);
}

void CrySearchForm::ToggleDebuggerWindow()
{
	// Attempt to close the tab if it is opened in the TabCtrl.
	const int i = IsTabPageOpened(this->mTabbedDataWindows, "Debugger");
	if (i >= 0)
	{
		this->mTabbedDataWindows.Remove(i);
		return;
	}
	
	// The tab is not opened, so open it.
	this->mTabbedDataWindows.Add(this->mDbgWindow.SizePos(), "Debugger");
	this->mTabbedDataWindows.Set(this->mDbgWindow);
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
		ClearSearchResults();
		this->mSearchResultCount.SetLabel("Search Results: 0");
	}
}

void CrySearchForm::ClearScanResultsWithoutWarning()
{
	this->mScanResults.Clear();
	ClearSearchResults();
	
	this->mSearchResultCount.SetLabel("Search Results: 0");
}

void CrySearchForm::WhenProcessOpened(Win32ProcessInformation& pProc)
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
	if (pProc.ProcessId == -1)
	{
		if (mMemoryScanner->Initialize(pProc.ExeTitle, &pProc.ProcessId))
		{
			// Wait for the process to be fully started, otherwise initialization steps will fail.
			Sleep(250);
			
			// Check if the process actually started correctly, if it didn't, the procedure failed.
			DWORD exitCode;
			if (GetExitCodeProcess(mMemoryScanner->GetHandle(), &exitCode) && exitCode == STILL_ACTIVE)
			{
#ifndef _WIN64
				this->mModuleList.Initialize();
				this->mThreadList.Initialize();
	
				// Check the architecture of the loaded process. Under x64, processes can cause trouble.
				if (mMemoryScanner->IsX86Process())
				{
					// Instantiate new PE class.
					mPeInstance = new PortableExecutable32();
					mDebugger = new CryDebugger32();
					this->mPEWindow.Initialize();
					this->mDisasmWindow.Initialize();
				}
				else
				{
					Prompt("Load Error", CtrlImg::error(), "Failed to open the selected process because it is 64-bit. Use CrySearch x64 to open it instead.", "OK");
					mMemoryScanner->CloseProcess();
					PostCallback(THISBACK(ReopenProcessMenu));
					return;
				}
#else
				this->mModuleList.Initialize();
				this->mThreadList.Initialize();
				
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
				
				this->mPEWindow.Initialize();
				this->mDisasmWindow.Initialize();
#endif
				this->mImportsWindow.Initialize();
				this->mDbgWindow.Initialize();
				
				// Still here so the process loaded succesfully. Update user interface and prepare tabs.
				this->processLoaded = true;
				this->mToolStrip.Set(THISBACK(ToolStrip));
				
				if (this->wndTitleRandomized)
				{
					this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
				}
				else
				{
					this->Title(Format("CrySearch Memory Scanner - (%i) %s", pProc.ProcessId, mMemoryScanner->GetProcessName()));
					this->mOpenedProcess.SetLabel("");
				}
				
				this->mMenuStrip.Set(THISBACK(MainMenu));
					
				this->mTabbedDataWindows.Add(this->mPEWindow.SizePos(), "General");
				this->mTabbedDataWindows.Add(this->mDisasmWindow.SizePos(), "Disassembly");
				this->mTabbedDataWindows.Add(this->mImportsWindow.SizePos(), "Imports");
				this->mTabbedDataWindows.Add(this->mThreadList.SizePos(), "Threads");
				this->mTabbedDataWindows.Add(this->mModuleList.SizePos(), "Modules");
				
				this->ProcessTerminated = false;
				SetTimeCallback(250, THISBACK(CheckProcessTermination), 30);
				SetTimeCallback(GlobalSettingsInstance.GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
				
				// Set process name in the address table using the value from the FileSel.
				loadedTable.SetProcessName(pProc.ExeTitle);
			}
			else
			{
				// CreateProcess succeeded, but the process is not started succesfully. For example: write.exe starts wordpad.exe and then terminates.
				Prompt("Load Error", CtrlImg::error(), "The process started succesfully but terminated before initialization. Possibly the process started another process and terminated.", "OK");
				mMemoryScanner->CloseProcess();
				PostCallback(THISBACK(ReopenProcessMenu));
			}
		}
		else
		{
			// CreateProcess failed, no process is loaded.
			Prompt("Load Error", CtrlImg::error(), "Failed to create the process.", "OK");
			PostCallback(THISBACK(ReopenProcessMenu));
		}
	}
	else
	{
		// Use process ID to open an existing process.
		if (mMemoryScanner->Initialize(pProc.ProcessId, pProc.ExeTitle))
		{
#ifndef _WIN64
			this->mModuleList.Initialize();
			this->mThreadList.Initialize();

			// A 64 bit process may not be loaded into 32 bit CrySearch. This check takes care of that.
			if (mMemoryScanner->IsX86Process())
			{
				// Instantiate new PE class.
				mPeInstance = new PortableExecutable32();
				mDebugger = new CryDebugger32();
				this->mPEWindow.Initialize();
				this->mDisasmWindow.Initialize();
			}
			else
			{
				Prompt("Load Error", CtrlImg::error(), "Failed to open the selected process because it is 64-bit. Use CrySearch x64 to open it instead.", "OK");
				mMemoryScanner->CloseProcess();
				PostCallback(THISBACK(ReopenProcessMenu));
				return;
			}
			
#else
			this->mModuleList.Initialize();
			this->mThreadList.Initialize();
			
			// Check whether the loaded process is x86 or x64 and create correct instances accordingly.
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
			
			this->mPEWindow.Initialize();
			this->mDisasmWindow.Initialize();
#endif
			
			this->mImportsWindow.Initialize();
			this->mDbgWindow.Initialize();
			
			// Still here so the process loaded succesfully. Update user interface and prepare tabs.
			this->processLoaded = true;
			this->mToolStrip.Set(THISBACK(ToolStrip));
			
			if (this->wndTitleRandomized)
			{
				this->mOpenedProcess.SetLabel(Format("(%i) %s ", mMemoryScanner->GetProcessId(), mMemoryScanner->GetProcessName()));
			}
			else
			{
				this->Title(Format("CrySearch Memory Scanner - (%i) %s", pProc.ProcessId, mMemoryScanner->GetProcessName()));
				this->mOpenedProcess.SetLabel("");
			}
			
			this->mMenuStrip.Set(THISBACK(MainMenu));
			
			// Add tabs to the tabcontrol.
			this->mTabbedDataWindows.Add(this->mPEWindow.SizePos(), "General");
			this->mTabbedDataWindows.Add(this->mDisasmWindow.SizePos(), "Disassembly");
			this->mTabbedDataWindows.Add(this->mImportsWindow.SizePos(), "Imports");
			this->mTabbedDataWindows.Add(this->mThreadList.SizePos(), "Threads");
			this->mTabbedDataWindows.Add(this->mModuleList.SizePos(), "Modules");
			
			this->ProcessTerminated = false;
			SetTimeCallback(250, THISBACK(CheckProcessTermination), 30);
			SetTimeCallback(GlobalSettingsInstance.GetAddressTableUpdateInterval(), THISBACK(AddressValuesUpdater), 10);
			
			// Since the process name is either retrieved or known, setting it here should not bring any problems.
			loadedTable.SetProcessName(mMemoryScanner->GetProcessName());
		}
	}
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
	switch (error)
	{
		case OPENPROCESSFAILED:
			// Kill timer callback, otherwise two error messages will pop up.
			KillTimeCallback(30);
			
			Prompt("Process Error", CtrlImg::error(), "Could not open the selected process. The process is either protected or 64-bit."\
				" To open a protected process, try running CrySearch as Administrator.", "OK");
			PostCallback(THISBACK(ReopenProcessMenu));
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
	bool million = ScanResultCount > MEMORYSCANNER_CACHE_LIMIT;
	
	if (million)
	{
		this->mScanResults.SetVirtualCount(MEMORYSCANNER_CACHE_LIMIT);
		this->mSearchResultCount.SetLabel(Format("Search Results: %i (100.000 results shown)", ScanResultCount));
	}
	else
	{
		this->mScanResults.SetVirtualCount(ScanResultCount);
		this->mSearchResultCount.SetLabel(Format("Search Results: %i", ScanResultCount));
	}
	
	this->mScanningProgress.Hide();
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	// Cheat Engine has this nice beep when a scan completes, why shouldn't I? :)
	BeepExclamation();
}

// Returns a pointer to the disassembly window.
CryDisasmCtrl* CrySearchForm::GetDisasmWindow()
{
	return &this->mDisasmWindow;
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

// Subwindows or controls that are managed by the main window class may be needed outside. A globally defined pointer is necessary.
CrySearchForm* frm;

GUI_APP_MAIN
{
	// Delete temporary files from any earlier run, which might have crashed.
	DeleteTemporaryFiles();
	
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
	
	// Run main window.
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