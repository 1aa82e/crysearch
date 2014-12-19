#ifndef _CrySearch_CrySearchForm_h_
#define _CrySearch_CrySearchForm_h_

#include "CryChangeRecordDialog.h"
#include "CrySearchArrayCtrl.h"
#include "AddressTable.h"
#include "CrySearchWindowManager.h"

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents the CrySearch main application window. Everything is initialized and operated from this.
class CrySearchForm : public TopWindow
{
private:
	bool processLoaded;
	bool ProcessTerminated;
	bool wndTitleRandomized;
	
	MenuBar mMenuStrip;
	ToolBar mToolStrip;
	Label mOpenedProcess;
	CrySearchArrayCtrl mScanResults;
	Splitter mMainSplitter;
	ParentCtrl mUserAddressPanel;
	CrySearchArrayCtrl mUserAddressList;
	Splitter mInputScanSplitter;
	ParentCtrl mSearchResultsPanel;
	Label mSearchResultCount;
	ProgressIndicator mScanningProgress;
	TabCtrl mTabbedDataWindows;
	
	// CrySearch window manager will proxy operations and data between the main window and backend.
	CrySearchWindowManager mWindowManager;

	void MainMenu(Bar& pBar);
	void ToolStrip(Bar& pBar);
	void FileMenu(Bar& pBar);
	void EditMenu(Bar& pBar);
	void ToolsMenu(Bar& pBar);
	void DebuggerMenu(Bar& pBar);
	void WindowMenu(Bar& pBar);
	void HelpMenu(Bar& pBar);
	void UserDefinedEntryWhenBar(Bar& pBar);
	void SearchResultWhenBar(Bar& pBar);
	void ChangeRecordSubMenu(Bar& pBar);
	void SetDataBreakpointMenu(Bar& pBar);
	
	void ViewSystemHandlesButtonClicked();
	void ActiveTabWindowChanged();
	void RandomizeWindowTitle();
	void SetBreakpointMenuFunction(const HWBP_TYPE type);
	void ToggleAlwaysOnTop();
	void SetDataBreakpointOnExecute();
	void SetDataBreakpointOnRead();
	void SetDataBreakpointOnReadWrite();
	void DebugWindowErrorOccured();
	void DebuggerAttachMenu();
	void DebuggerDetachMenu();
	void AllocateMemoryButtonClicked();
	void ViewPEBButtonClicked();
	void CodeGenerationButtonClicked();
	void MemoryDissectionButtonClicked();
	void ToggleDebuggerWindow();
	void ToggleAddressTableFreezeThaw();
	void ToggleAddressTableValueView();
	void AddressListEntryMemoryDissection();
	void OpenProcessMenu();
	void CloseProcessMenu();
	bool CloseProcess();
	void SettingsButtonClicked();
	void ViewModulesButtonClicked();
	void ViewThreadsButtonClicked();
	void ViewGeneralButtonClicked();
	void ViewImportsButtonClicked();
	void ExitApplication();
	void AboutCrySearch();
	void ClearScanResults();
	void ClearScanResultsWithoutWarning();
	void SearchResultDoubleClicked();
	void DeleteUserDefinedAddress();
	void OpenFileMenu();
	void SaveFileMenu();
	void SaveFileAsMenu();
	void ClearAddressList();
	void ShowHideDisasmWindow();
	void ManuallyAddAddressToTable();
	void AddressListChangeProperty(ChangeRecordDialogMode mode);
	void UserDefinedEntryWhenDoubleClicked();
	void UpdateVisibleAddresses();
	void SearchResultListUpdater();
	void AddressValuesUpdater();
	void CheckKeyPresses();
	void CheckProcessTermination();
	void LinkHotkeysToActions();
	void RemoveBreakpointMenu();
	void PluginsMenuClicked();
	
	bool InitializeProcessUI();
	void WhenProcessOpened(Win32ProcessInformation* pProc);
	void MemorySearch();
	void RefreshSearchResults();
	void StartNextScanHotkey();
	void StartMemoryScanReliefGUI(bool FirstScan);
	void ScannerCompletedScan();
	void ScannerCompletedThreadSafe();
	void ScannerErrorOccured(MemoryScannerError error);
	void ScannerErrorOccuredThreadSafe(MemoryScannerError error);
	void ScannerUserInterfaceUpdate(Atomic threadCount);
	void ScannerUserInterfaceUpdateThreadSafe(Atomic threadCount);
	void ScannerScanStarted(int threadCount);
	void ScannerScanStartedThreadSafe(int threadCount);
	
	typedef CrySearchForm CLASSNAME;
public:
	CrySearchForm(const char* fn);
	~CrySearchForm();
	
	CrySearchWindowManager* GetWindowManager();
	CrySearchArrayCtrl* GetSearchResultCtrl();
	
	bool SetActiveTabWindow(const String& wndText);
};

#endif
