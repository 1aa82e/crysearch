#ifndef _CrySearch_CrySearchForm_h_
#define _CrySearch_CrySearchForm_h_

#include "CryChangeRecordDialog.h"
#include "CrySearchArrayCtrl.h"
#include "AddressTable.h"
#include "CrySearchWindowManager.h"
#include "CrashHandler.h"

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents the CrySearch main application window. Everything is initialized and operated from this.
class CrySearchForm : public TopWindow
{
private:
	bool processLoaded;
	bool ProcessTerminated;
	bool wndTitleRandomized;
	bool lowerPaneHidden;
	
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
	
	void AddressTableRemovalRoutine(const Vector<int>& items);
	void SetMainSplitterPosition();
	void HideLowerPaneButtonClicked();
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
	void FillMemoryButtonClicked();
	void ViewPEBButtonClicked();
	void MemoryDissectionButtonClicked();
	void ToggleDebuggerWindow();
	void ToggleAddressTableFreezeThaw();
	void ToggleAddressTableValueView();
	void ToggleSearchResultViewAs();
	void AddressListEntryMemoryDissection();
	void HeapWalkMenuClicked();
	void CodeCaveMenuClicked();
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
	void RemoveBreakpointMenu();
	void PluginsMenuClicked();
	void BruteForcePIDClicked();
	void ExecuteCrashHandlerWindowSafe(const String& msg, volatile bool* const comp);
	
	// Hotkey functions.
	void HotkeysProcedure();
	void LinkHotkeysToActions();
	void HotkeyRefreshChanged();
	void HotkeyRefreshUnchanged();
	void HotkeyRefreshIncreased();
	void HotkeyRefreshDecreased();
	void HotkeyRefreshToggelFreezeAll();
	
	bool InitializeProcessUI(const bool bruteForce);
	void ProcessOpenFailedState(const bool bruteForce);
	void WhenProcessOpened(Win32ProcessInformation* pProc, const bool bruteForce);
	void MemorySearch();
	void RefreshSearchResults();
	void StartNextScanHotkey();
	void StartMemoryScanReliefGUI(const bool FirstScan);
	void ScannerCompletedScan();
	void ScannerCompletedThreadSafe();
	void ScannerErrorOccured(MemoryScannerError error);
	void ScannerErrorOccuredThreadSafe(MemoryScannerError error);
	void ScannerUserInterfaceUpdate(int threadCount);
	void ScannerUserInterfaceUpdateThreadSafe(int threadCount);
	void ScannerScanStarted(int threadCount);
	void ScannerScanStartedThreadSafe(int threadCount);
	void ScannerPeekCompletion();
	
	typedef CrySearchForm CLASSNAME;
public:
	CrySearchForm(const char* fn);
	~CrySearchForm();
	
	CrySearchWindowManager* GetWindowManager();
	CrySearchArrayCtrl* GetSearchResultCtrl();
	
	void ExecuteCrashHandlerWindow(const String& msg);
	bool SetActiveTabWindow(const String& wndText);
};

#endif
