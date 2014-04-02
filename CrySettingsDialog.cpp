#include "CrySettingsDialog.h"
#include "ImlProvider.h"
#include "CryAddHotkeyWindow.h"

extern String& HotkeyToString(const unsigned int hotkey);

// File extension functions.
extern "C" const BOOL RegisterAddressTableExtension();
extern "C" const BOOL GetIsAddressTableExtensionRegistered();
extern "C" const BOOL DeleteAddressTableRegistration();

String GetHotkeyKey(const unsigned int index)
{
	return HotkeyToString(GlobalSettingsInstance.GetHotkey(index).Key);
}

String GetHotkeyAction(const unsigned int index)
{
	return GlobalSettingsInstance.GetHotkey(index).Description;
}

String GetSymbolPathString(const int index)
{
	return GlobalSettingsInstance.GetSymbolPath(index);
}

CrySearchSettingsDialog::CrySearchSettingsDialog()
{
	this->Title("Settings").Icon(CrySearchIml::SettingsButton).SetRect(0, 0, 400, 300);
	
	this->mOk <<= THISBACK(SettingsOk);
	this->mCancel <<= THISBACK(SettingsCancel);
	
	this->mAddHotkey <<= THISBACK(AddHotkeyToList);
	this->mBrowseSymbolPath <<= THISBACK(AddSymbolPathToList);
	this->mSymbolPathsList.WhenBar = THISBACK(WhenRightClickSymbolPathList);
	this->mHotkeysOption.WhenAction = THISBACK(HotkeyEnablerChanged);
	this->dbgInvadeProcess.WhenAction = THISBACK(InvadeProcessEnablerChanged);
	this->mHotkeysList.WhenBar = THISBACK(WhenRightClickHotkeyList);
	
	this->mHotkeysList.AddRowNumColumn("Action", 75).SetConvert(Single<HotkeyValueConvert<GetHotkeyAction>>());
	this->mHotkeysList.AddRowNumColumn("Hotkey", 25).SetConvert(Single<HotkeyValueConvert<GetHotkeyKey>>());
	this->mSymbolPathsList.AddRowNumColumn("Path").SetConvert(Single<IndexBasedValueConvert<GetSymbolPathString>>());
	
	this->mScanningTab
		<< this->fastScanByDefault.SetLabel("Use a fast scan by default").HSizePos(5, 5).TopPos(0, 20)
		<< this->mScanProtectionTypes.SetLabel("Protected regions to scan").HSizePos(5, 5).TopPos(20, 75)
		<< this->scanWritable.SetLabel("Writable").HSizePos(10, 10).TopPos(36, 20)
		<< this->scanExecutable.SetLabel("Executable").HSizePos(10, 10).TopPos(55, 20)
		<< this->scanCopyOnWrite.SetLabel("CopyOnWrite").HSizePos(10, 10).TopPos(73, 20)
		<< this->mScanTypes.SetLabel("Region types to scan").HSizePos(5, 5).TopPos(100, 72)
		<< this->memPrivate.SetLabel("MEM_PRIVATE").HSizePos(10, 10).TopPos(117, 20)
		<< this->memImage.SetLabel("MEM_IMAGE").HSizePos(10, 10).TopPos(134, 20)
		<< this->memMapped.SetLabel("MEM_MAPPED").HSizePos(10, 10).TopPos(151, 20)
		<< this->mScanThreadProperties.SetLabel("Scanning thread properties").HSizePos(5, 5).TopPos(175, 50)
		<< this->scanningThreadPriorityLabel.SetLabel("Scan worker thread priority:").HSizePos(10, 160)
			.TopPos(193, 20)
		<< this->scanningThreadPriority.Add("Lowest").Add("Below Normal").Add("Normal").Add("Above Normal")
			.Add("Highest").HSizePos(210, 10).TopPos(193, 20)
	;
	
	this->mGeneralTab
		<< this->mAddressTableUpdaterIntervalBox.SetLabel("Address table updater").HSizePos(5, 5).TopPos(0, 45)
		<< this->mAddressTableUpdaterIntervalDescription.SetLabel("Update Interval:").HSizePos(10, 120).TopPos(18, 20)
		<< this->mAddressTableUpdaterIntervalEditField.HSizePos(150, 10).TopPos(18, 20)
		<< this->mRoutinesBox.SetLabel("Routines").HSizePos(5, 5).TopPos(50, 45)
		<< this->mOpenProcRoutineSelectorLabel.SetLabel("Opening a process:").HSizePos(10, 90).TopPos(68, 20)
		<< this->mOpenProcRoutineSelector.Add("OpenProcess (Default)").Add("NtOpenProcess").HSizePos(150, 10).TopPos(68, 20)
		<< this->mRegisterFileExtensionWithCrySearch.SetLabel("Associate address table files with CrySearch.").HSizePos(5, 5).BottomPos(5, 20)
	;
	
	this->mDebuggerTab
		<< this->mStackSnapshotLimitDescriptor.SetLabel("Stack snapshot read limit:").LeftPos(5, 180).TopPos(5, 20)
		<< this->mStackSnapshotLimitEdit.HSizePos(200, 5).TopPos(5, 20)
		<< this->dbgAttemptHidePeb.SetLabel("Attempt to hide the debugger from PEB").HSizePos(5, 5).TopPos(28, 20)
		<< this->dbgInvadeProcess.SetLabel("Attempt to load symbols for all modules").HSizePos(5, 5).TopPos(48, 20)
		<< this->mSymbolPathsDescriptor.SetLabel("Symbol Paths:").HSizePos(5, 5).TopPos(110, 20)
		<< this->mBrowseSymbolPath.SetLabel("Add").RightPos(5, 60).TopPos(110, 20)
		<< this->mSymbolPathsList.HSizePos(5, 5).VSizePos(135, 5)
	;
	
	this->mHotkeysTab
		<< this->mHotkeysOption.SetLabel("Enable hotkeys").HSizePos(5, 5).TopPos(5, 20)
		<< this->mAddHotkey.SetLabel("Add").RightPos(5, 60).TopPos(5, 20)
		<< this->mHotkeysList.HSizePos(5, 5).VSizePos(30, 5)
	;
	
	*this
		<< this->mainTabCtrl
		<< this->mOk.Ok().SetLabel("OK").HSizePos(340, 5).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").HSizePos(280, 60).BottomPos(5, 25)
	;
	
	this->mainTabCtrl.Add(this->mScanningTab.SizePos(), "Scanning");
	this->mainTabCtrl.Add(this->mGeneralTab.SizePos(), "General");
	this->mainTabCtrl.Add(this->mDebuggerTab.SizePos(), "Debugger");
	this->mainTabCtrl.Add(this->mHotkeysTab.SizePos(), "Hotkeys");
	this->mainTabCtrl.SetRect(0, 0, 400, 265);
	this->Add(mainTabCtrl);
	
	this->LoadSettings();
}

void CrySearchSettingsDialog::LoadSettings()
{
	// Load settings from file into static controls.
	this->fastScanByDefault = GlobalSettingsInstance.GetFastScanByDefault();
	this->scanWritable = GlobalSettingsInstance.GetScanWritableMemory();
	this->scanExecutable = GlobalSettingsInstance.GetScanExecutableMemory();
	this->scanCopyOnWrite = GlobalSettingsInstance.GetScanCopyOnWriteMemory();
	this->memPrivate = GlobalSettingsInstance.GetScanMemPrivate();
	this->memImage = GlobalSettingsInstance.GetScanMemImage();
	this->memMapped = GlobalSettingsInstance.GetScanMemMapped();
	this->scanningThreadPriority.SetIndex(GlobalSettingsInstance.GetScanThreadPriority());
	this->mOpenProcRoutineSelector.SetIndex(GlobalSettingsInstance.GetOpenProcessRoutine());
	this->mAddressTableUpdaterIntervalEditField.SetText(IntStr(GlobalSettingsInstance.GetAddressTableUpdateInterval()));
	this->mStackSnapshotLimitEdit.SetText(IntStr(GlobalSettingsInstance.GetStackSnapshotLimit()));
	this->dbgAttemptHidePeb = GlobalSettingsInstance.GetAttemptHideDebuggerFromPeb();
	this->mHotkeysOption = GlobalSettingsInstance.GetEnableHotkeys();
	this->dbgInvadeProcess = GlobalSettingsInstance.GetInvadeProcess();
	
	// Based on the loaded settings, make sure the disable/enable options are set correctly.
	this->InvadeProcessEnablerChanged();
	this->HotkeyEnablerChanged();
	
	// Set virtual arrays to display settings correctly.
	this->mHotkeysList.SetVirtualCount(GlobalSettingsInstance.GetHotkeyCount());
	this->mSymbolPathsList.SetVirtualCount(GlobalSettingsInstance.GetSymbolPathCount());
	
	this->mRegisterFileExtensionWithCrySearch = GetIsAddressTableExtensionRegistered();
	this->mStartCheckedExtensionState = this->mRegisterFileExtensionWithCrySearch;
}

void CrySearchSettingsDialog::SaveSettings()
{	
	// Save static controls to settings file.
	GlobalSettingsInstance.SetFastScanByDefault(this->fastScanByDefault);
	GlobalSettingsInstance.SetScanWritableMemory(this->scanWritable);
	GlobalSettingsInstance.SetScanExecutableMemory(this->scanExecutable);
	GlobalSettingsInstance.SetScanCopyOnWriteMemory(this->scanCopyOnWrite);
	GlobalSettingsInstance.SetScanMemPrivate(this->memPrivate);
	GlobalSettingsInstance.SetScanMemImage(this->memImage);
	GlobalSettingsInstance.SetScanMemMapped(this->memMapped);
	GlobalSettingsInstance.SetScanThreadPriority(this->scanningThreadPriority.GetIndex());
	GlobalSettingsInstance.SetOpenProcessRoutine(this->mOpenProcRoutineSelector.GetIndex());	
	GlobalSettingsInstance.SetAttemptHideDebuggerFromPeb(this->dbgAttemptHidePeb);
	GlobalSettingsInstance.SetEnableHotkeys(this->mHotkeysOption);
	GlobalSettingsInstance.SetInvadeProcess(this->dbgInvadeProcess);
	
	// Attempt registering the CrySearch address table file extension with the currently started architecture of CrySearch.
	if (this->mRegisterFileExtensionWithCrySearch && !this->mStartCheckedExtensionState && !RegisterAddressTableExtension())
	{
		Prompt("Fatal Error", CtrlImg::error(), "Failed to register the file extension. Please run CrySearch as Administrator.", "OK");
	}
	else if (!this->mRegisterFileExtensionWithCrySearch && this->mStartCheckedExtensionState && !DeleteAddressTableRegistration())
	{
		Prompt("Fatal Error", CtrlImg::error(), "Failed to delete the file extension from the registry. Please run CrySearch as Administrator.", "OK");
	}
	
	GlobalSettingsInstance.Save();
}

void CrySearchSettingsDialog::AddHotkeyToList()
{
	CryAddHotkeyWindow* cahw = new CryAddHotkeyWindow(NULL);
	cahw->Execute();
	delete cahw;
	this->mHotkeysList.SetVirtualCount(GlobalSettingsInstance.GetHotkeyCount());
}

void CrySearchSettingsDialog::InvadeProcessEnablerChanged()
{
	this->mSymbolPathsDescriptor.Enable(!this->dbgInvadeProcess);
	this->mBrowseSymbolPath.Enable(!this->dbgInvadeProcess);
	this->mSymbolPathsList.Enable(!this->dbgInvadeProcess);
}

void CrySearchSettingsDialog::HotkeyEnablerChanged()
{
	this->mAddHotkey.Enable(this->mHotkeysOption);
	this->mHotkeysList.Enable(this->mHotkeysOption);
}

void CrySearchSettingsDialog::WhenRightClickHotkeyList(Bar& pBar)
{
	if (this->mHotkeysList.GetCursor() >= 0 && GlobalSettingsInstance.GetHotkeyCount() > 0)
	{
		pBar.Add("Edit", CrySearchIml::ChangeRecordIcon(), THISBACK(EditHotkeyFromList));
		pBar.Separator();
		pBar.Add("Delete", CrySearchIml::DeleteButton(), THISBACK(DeleteHotkeyFromList));
	}
}

void CrySearchSettingsDialog::WhenRightClickSymbolPathList(Bar& pBar)
{
	if (this->mSymbolPathsList.GetCursor() >= 0 && GlobalSettingsInstance.GetSymbolPathCount() > 0)
	{
		pBar.Add("Delete", CrySearchIml::DeleteButton(), THISBACK(DeleteSymbolPathFromList));
	}
}

void CrySearchSettingsDialog::EditHotkeyFromList()
{
	CryAddHotkeyWindow* cahw = new CryAddHotkeyWindow(&GlobalSettingsInstance.GetHotkey(this->mHotkeysList.GetCursor()));
	cahw->Execute();
	delete cahw;
	this->mHotkeysList.SetVirtualCount(GlobalSettingsInstance.GetHotkeyCount());
}

void CrySearchSettingsDialog::DeleteHotkeyFromList()
{
	GlobalSettingsInstance.DeleteHotKey(this->mHotkeysList.GetCursor());
	this->mHotkeysList.SetVirtualCount(GlobalSettingsInstance.GetHotkeyCount());
}

void CrySearchSettingsDialog::AddSymbolPathToList()
{
	FileSel* fs = new FileSel;
	if (fs->ExecuteSelectDir("Select Directory...") && !GlobalSettingsInstance.AddSymbolPath(fs->Get()))
	{
		Prompt("Input Error", CtrlImg::error(), "The selected path was already added!", "OK");
	}
	
	this->mSymbolPathsList.SetVirtualCount(GlobalSettingsInstance.GetSymbolPathCount());
	delete fs;
}

void CrySearchSettingsDialog::DeleteSymbolPathFromList()
{
	GlobalSettingsInstance.DeleteSymbolPath(this->mSymbolPathsList.GetCursor());
	this->mSymbolPathsList.SetVirtualCount(GlobalSettingsInstance.GetSymbolPathCount());
}

void CrySearchSettingsDialog::SettingsOk()
{
	// Check input values for possible errors.
	const int interval = StrInt(this->mAddressTableUpdaterIntervalEditField.GetText().ToString());
	if (((String)this->mAddressTableUpdaterIntervalEditField).IsEmpty() || interval <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "The updater interval value is invalid.", "OK");
		return;
	}
	else
	{
		GlobalSettingsInstance.SetAddressTableUpdateInterval(interval);
	}
	
	const int stackLimit = StrInt(this->mStackSnapshotLimitEdit.GetText().ToString());
	if (((String)this->mStackSnapshotLimitEdit).IsEmpty() || stackLimit <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "The stack snapshot limit value is invalid.", "OK");
		return;
	}
	else if (!GetIsMultipleOf(stackLimit, sizeof(LONG)))
	{
		Prompt("Input Error", CtrlImg::error(), "The stack snapshot limit value must be a multiple of 4.", "OK");
		return;
	}
	else
	{
		GlobalSettingsInstance.SetStackSnapshotLimit(stackLimit);
	}
	
	this->SaveSettings();
	this->Close();
}

void CrySearchSettingsDialog::SettingsCancel()
{
	this->Close();
}