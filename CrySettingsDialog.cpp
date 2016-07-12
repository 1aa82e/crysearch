#include "CrySettingsDialog.h"
#include "ImlProvider.h"
#include "CryAddHotkeyWindow.h"
#include "UIUtilities.h"

extern const char* HotkeyToString(const unsigned int hotkey);

// File extension functions.
extern "C" const BOOL RegisterAddressTableExtension();
extern "C" const BOOL GetIsAddressTableExtensionRegistered();
extern "C" const BOOL DeleteAddressTableRegistration();

String GetHotkeyKey(const int index)
{
	return HotkeyToString(SettingsFile::GetInstance()->GetHotkey(index).Key);
}

String GetHotkeyAction(const int index)
{
	return SettingsFile::GetInstance()->GetHotkey(index).Description;
}

String GetSymbolPathString(const int index)
{
	return SettingsFile::GetInstance()->GetSymbolPath(index);
}

CrySearchSettingsDialog::CrySearchSettingsDialog()
{
	this->mSettingsInstance = SettingsFile::GetInstance();
	this->Title("Settings").Icon(CrySearchIml::SettingsButton).SetRect(0, 0, 420, 330);
	
	this->mOk <<= THISBACK(SettingsOk);
	this->mCancel <<= THISBACK(SettingsCancel);
	
	this->mAddHotkey <<= THISBACK(AddHotkeyToList);
	this->mBrowseSymbolPath <<= THISBACK(AddSymbolPathToList);
	this->mSymbolPathsList.WhenBar = THISBACK(WhenRightClickSymbolPathList);
	this->mHotkeysOption.WhenAction = THISBACK(HotkeyEnablerChanged);
	this->dbgInvadeProcess.WhenAction = THISBACK(InvadeProcessEnablerChanged);
	this->mHotkeysList.WhenBar = THISBACK(WhenRightClickHotkeyList);
	
	this->mHotkeysList.CryAddRowNumColumn("Action", 75).SetConvert(Single<IndexBasedValueConvert<GetHotkeyAction>>());
	this->mHotkeysList.CryAddRowNumColumn("Hotkey", 25).SetConvert(Single<IndexBasedValueConvert<GetHotkeyKey>>());
	this->mSymbolPathsList.CryAddRowNumColumn("Path").SetConvert(Single<IndexBasedValueConvert<GetSymbolPathString>>());
	
	this->mScanningTab
		<< this->fastScanByDefault.SetLabel("Use a fast scan by default").HSizePos(5, 5).TopPos(0, 20)
		<< this->mScanProtectionTypes.SetLabel("Protected regions to scan").HSizePos(5, 5).TopPos(25, 45)
		<< this->scanWritable.SetLabel("Writable").HSizePos(10, 300).TopPos(43, 20)
		<< this->scanExecutable.SetLabel("Executable").HSizePos(150, 140).TopPos(43, 20)
		<< this->scanCopyOnWrite.SetLabel("CopyOnWrite").HSizePos(270, 10).TopPos(43, 20)
		<< this->mScanTypes.SetLabel("Region types to scan").HSizePos(5, 5).TopPos(70, 80)
		<< this->memPrivate.SetLabel("MEM_PRIVATE").HSizePos(10, 10).TopPos(87, 20)
		<< this->memImage.SetLabel("MEM_IMAGE").HSizePos(10, 10).TopPos(107, 20)
		<< this->memMapped.SetLabel("MEM_MAPPED").HSizePos(10, 10).TopPos(127, 20)
		<< this->mScanThreadProperties.SetLabel("Scanning thread properties").HSizePos(5, 5).TopPos(153, 50)
		<< this->scanningThreadPriorityLabel.SetLabel("Scan worker thread priority:").HSizePos(10, 160)
			.TopPos(170, 25)
		<< this->scanningThreadPriority.Add("Lowest").Add("Below Normal").Add("Normal").Add("Above Normal")
			.Add("Highest").HSizePos(210, 10).TopPos(170, 25)
		<< this->mCrySearchInReadOnlyMode.SetLabel("Enable read-only mode").TopPos(210, 22).HSizePos(10, 10)
	;
	
	this->mInternalsTab
		<< this->mAddressTableUpdaterIntervalBox.SetLabel("Address table updater").HSizePos(5, 5).TopPos(0, 47)
		<< this->mAddressTableUpdaterIntervalDescription.SetLabel("Update Interval:").HSizePos(10, 120).TopPos(18, 25)
		<< this->mAddressTableUpdaterIntervalEditField.HSizePos(150, 10).TopPos(18, 25)
		<< this->mRoutinesBox.SetLabel("Routines").HSizePos(5, 5).VSizePos(46, 67)
		<< this->mOpenProcRoutineSelectorLabel.SetLabel("Opening a process:").HSizePos(10, 90).TopPos(61, 25)
		<< this->mOpenProcRoutineSelector.Add("OpenProcess (Default)").Add("NtOpenProcess").HSizePos(150, 10).TopPos(61, 25)
		<< this->mReadMemoryProcRoutineSelectorLabel.SetLabel("Reading memory:").HSizePos(10, 90).TopPos(89, 25)
		<< this->mReadMemoryProcRoutineSelector.Add("ReadProcessMemory (Default)").Add("NtReadVirtualMemory").HSizePos(150, 10).TopPos(89, 25)
		<< this->mWriteMemoryProcRoutineSelectorLabel.SetLabel("Writing memory:").HSizePos(10, 90).TopPos(117, 25)
		<< this->mWriteMemoryProcRoutineSelector.Add("WriteProcessMemory (Default)").Add("NtWriteVirtualMemory").HSizePos(150, 10).TopPos(117, 25)
		<< this->mProtectMemoryProcRoutineSelectorLabel.SetLabel("Protecting memory:").HSizePos(10, 90).TopPos(145, 25)
		<< this->mProtectMemoryProcRoutineSelector.Add("VirtualProtectEx (Default)").Add("NtProtectVirtualMemory").HSizePos(150, 10).TopPos(145, 25)
		<< this->mInjectionBox.SetLabel("Library Injection").HSizePos(5, 5).VSizePos(180, 25)
		<< this->mInjectionMethodDescriptor.SetLabel("Injection method:").HSizePos(10, 90).TopPos(190, 25)
		<< this->mInjectionMethod.Add("CreateRemoteThread (Default)").Add("Hijack thread").HSizePos(150, 10).TopPos(190, 25)
		<< this->mRegisterFileExtensionWithCrySearch.SetLabel("Associate address table files with CrySearch.").HSizePos(5, 5).BottomPos(0, 25)
	;
	
	this->mDebuggerTab
		<< this->mStackSnapshotLimitDescriptor.SetLabel("Stack snapshot read limit:").LeftPos(5, 180).TopPos(5, 25)
		<< this->mStackSnapshotLimitEdit.HSizePos(200, 5).TopPos(5, 25)
		<< this->dbgAttemptHidePeb.SetLabel("Attempt to hide the debugger from PEB").HSizePos(5, 5).TopPos(35, 20)
		<< this->dbgCatchAllExceptions.SetLabel("Catch all exceptions").HSizePos(5, 5).TopPos(60, 20)
		<< this->dbgInvadeProcess.SetLabel("Attempt to load symbols for all modules").HSizePos(5, 5).TopPos(85, 20)
		<< this->mSymbolPathsDescriptor.SetLabel("Symbol Paths:").HSizePos(5, 5).TopPos(110, 25)
		<< this->mBrowseSymbolPath.SetLabel("Add").RightPos(5, 60).TopPos(110, 25)
		<< this->mSymbolPathsList.HSizePos(5, 5).VSizePos(140, 5)
	;
	
	this->mHotkeysTab
		<< this->mHotkeysOption.SetLabel("Enable hotkeys").HSizePos(5, 100).TopPos(5, 25)
		<< this->mAddHotkey.SetLabel("Add").RightPos(5, 60).TopPos(5, 25)
		<< this->mHotkeysList.HSizePos(5, 5).VSizePos(35, 5)
	;
	
	*this
		<< this->mainTabCtrl
		<< this->mOk.Ok().SetLabel("OK").HSizePos(340, 5).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").HSizePos(255, 85).BottomPos(5, 25)
	;
	
	this->mainTabCtrl.Add(this->mScanningTab.SizePos(), "Scanning");
	this->mainTabCtrl.Add(this->mInternalsTab.SizePos(), "Internals");
	this->mainTabCtrl.Add(this->mDebuggerTab.SizePos(), "Debugger");
	this->mainTabCtrl.Add(this->mHotkeysTab.SizePos(), "Hotkeys");
	this->mainTabCtrl.SetRect(0, 0, 420, 280);
	this->Add(mainTabCtrl);
	
	this->LoadSettings();
}

void CrySearchSettingsDialog::LoadSettings()
{
	// Load settings from file into static controls.
	this->fastScanByDefault = this->mSettingsInstance->GetFastScanByDefault();
	this->scanWritable = this->mSettingsInstance->GetScanWritableMemory();
	this->scanExecutable = this->mSettingsInstance->GetScanExecutableMemory();
	this->scanCopyOnWrite = this->mSettingsInstance->GetScanCopyOnWriteMemory();
	this->memPrivate = this->mSettingsInstance->GetScanMemPrivate();
	this->memImage = this->mSettingsInstance->GetScanMemImage();
	this->memMapped = this->mSettingsInstance->GetScanMemMapped();
	this->scanningThreadPriority.SetIndex(this->mSettingsInstance->GetScanThreadPriority());
	this->mOpenProcRoutineSelector.SetIndex(this->mSettingsInstance->GetOpenProcessRoutine());
	this->mReadMemoryProcRoutineSelector.SetIndex(this->mSettingsInstance->GetReadMemoryRoutine());
	this->mWriteMemoryProcRoutineSelector.SetIndex(this->mSettingsInstance->GetWriteMemoryRoutine());
	this->mProtectMemoryProcRoutineSelector.SetIndex(this->mSettingsInstance->GetProtectMemoryRoutine());
	this->mInjectionMethod.SetIndex(this->mSettingsInstance->GetLibraryInjectionMethod());
	this->mAddressTableUpdaterIntervalEditField.SetText(FormatIntSpecial(this->mSettingsInstance->GetAddressTableUpdateInterval()));
	this->mStackSnapshotLimitEdit.SetText(FormatIntSpecial(this->mSettingsInstance->GetStackSnapshotLimit()));
	this->dbgAttemptHidePeb = this->mSettingsInstance->GetAttemptHideDebuggerFromPeb();
	this->mHotkeysOption = this->mSettingsInstance->GetEnableHotkeys();
	this->dbgInvadeProcess = this->mSettingsInstance->GetInvadeProcess();
	this->dbgCatchAllExceptions = this->mSettingsInstance->GetCatchAllExceptions();
	this->mCrySearchInReadOnlyMode = this->mSettingsInstance->GetEnableReadOnlyMode();
	
	// Based on the loaded settings, make sure the disable/enable options are set correctly.
	this->InvadeProcessEnablerChanged();
	this->HotkeyEnablerChanged();
	
	// Set virtual arrays to display settings correctly.
	this->mHotkeysList.SetVirtualCount(this->mSettingsInstance->GetHotkeyCount());
	this->mSymbolPathsList.SetVirtualCount(this->mSettingsInstance->GetSymbolPathCount());
	
	this->mRegisterFileExtensionWithCrySearch = !!GetIsAddressTableExtensionRegistered();
	this->mStartCheckedExtensionState = this->mRegisterFileExtensionWithCrySearch;
}

void CrySearchSettingsDialog::SaveSettings()
{
	const DWORD appname[] = {0x53797243, 0x63726165, 0x68}; //"CrySearch"
	
	// Save static controls to settings file.
	this->mSettingsInstance->SetFastScanByDefault(this->fastScanByDefault);
	this->mSettingsInstance->SetScanWritableMemory(this->scanWritable);
	this->mSettingsInstance->SetScanExecutableMemory(this->scanExecutable);
	this->mSettingsInstance->SetScanCopyOnWriteMemory(this->scanCopyOnWrite);
	this->mSettingsInstance->SetScanMemPrivate(this->memPrivate);
	this->mSettingsInstance->SetScanMemImage(this->memImage);
	this->mSettingsInstance->SetScanMemMapped(this->memMapped);
	this->mSettingsInstance->SetScanThreadPriority(this->scanningThreadPriority.GetIndex());
	this->mSettingsInstance->SetOpenProcessRoutine(this->mOpenProcRoutineSelector.GetIndex());
	this->mSettingsInstance->SetReadMemoryRoutine(this->mReadMemoryProcRoutineSelector.GetIndex());
	this->mSettingsInstance->SetWriteMemoryRoutine(this->mWriteMemoryProcRoutineSelector.GetIndex());
	this->mSettingsInstance->SetProtectMemoryRoutine(this->mProtectMemoryProcRoutineSelector.GetIndex());
	this->mSettingsInstance->SetLibraryInjectionMethod(this->mInjectionMethod.GetIndex());
	this->mSettingsInstance->SetAttemptHideDebuggerFromPeb(this->dbgAttemptHidePeb);
	this->mSettingsInstance->SetEnableHotkeys(this->mHotkeysOption);
	this->mSettingsInstance->SetInvadeProcess(this->dbgInvadeProcess);
	this->mSettingsInstance->SetCatchAllExceptions(this->dbgCatchAllExceptions);
	
	// Check if the read-only option for CrySearch was changed. If it was, inform the user that
	// this will be applied when the process is closed and reopened.
	if (!!this->mCrySearchInReadOnlyMode != this->mSettingsInstance->GetEnableReadOnlyMode() && mMemoryScanner->GetProcessId())
	{
		Prompt("Behavioral Warning", CtrlImg::exclamation(), "The read-only mode setting has changed. This change will be applied on process closing and reopening.", "OK");
	}
	
	this->mSettingsInstance->SetEnableReadOnlyMode(this->mCrySearchInReadOnlyMode);
	
	// As a special case, update the search routine in this part of the program.
	CrySearchRoutines.InitializeRoutines();
	
	// Attempt registering the CrySearch address table file extension with the currently started architecture of CrySearch.
	if (this->mRegisterFileExtensionWithCrySearch && !this->mStartCheckedExtensionState && !RegisterAddressTableExtension())
	{
		Prompt("Fatal Error", CtrlImg::error(), Format("Failed to register the file extension. Please run %s as Administrator.", (char*)appname), "OK");
	}
	else if (!this->mRegisterFileExtensionWithCrySearch && this->mStartCheckedExtensionState && !DeleteAddressTableRegistration())
	{
		Prompt("Fatal Error", CtrlImg::error(), Format("Failed to delete the file extension from the registry. Please run %s as Administrator.", (char*)appname), "OK");
	}
	
	this->mSettingsInstance->Save();
}

void CrySearchSettingsDialog::AddHotkeyToList()
{
	CryAddHotkeyWindow* cahw = new CryAddHotkeyWindow(NULL, CrySearchIml::AddToAddressList());
	cahw->Execute();
	delete cahw;
	this->mHotkeysList.SetVirtualCount(this->mSettingsInstance->GetHotkeyCount());
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
	if (this->mHotkeysList.GetCursor() >= 0 && this->mSettingsInstance->GetHotkeyCount() > 0)
	{
		pBar.Add("Edit", CrySearchIml::ChangeRecordIcon(), THISBACK(EditHotkeyFromList));
		pBar.Separator();
		pBar.Add("Delete", CrySearchIml::DeleteButton(), THISBACK(DeleteHotkeyFromList));
	}
}

void CrySearchSettingsDialog::WhenRightClickSymbolPathList(Bar& pBar)
{
	if (this->mSymbolPathsList.GetCursor() >= 0 && this->mSettingsInstance->GetSymbolPathCount() > 0)
	{
		pBar.Add("Delete", CrySearchIml::DeleteButton(), THISBACK(DeleteSymbolPathFromList));
	}
}

void CrySearchSettingsDialog::EditHotkeyFromList()
{
	CryAddHotkeyWindow* cahw = new CryAddHotkeyWindow(&this->mSettingsInstance->GetHotkey(this->mHotkeysList.GetCursor()), CrySearchIml::ChangeRecordIcon());
	cahw->Execute();
	delete cahw;
	this->mHotkeysList.SetVirtualCount(this->mSettingsInstance->GetHotkeyCount());
}

void CrySearchSettingsDialog::DeleteHotkeyFromList()
{
	this->mSettingsInstance->DeleteHotKey(this->mHotkeysList.GetCursor());
	this->mHotkeysList.SetVirtualCount(this->mSettingsInstance->GetHotkeyCount());
}

void CrySearchSettingsDialog::AddSymbolPathToList()
{
	FileSel* fs = new FileSel();
	if (fs->ExecuteSelectDir("Select Directory...") && !this->mSettingsInstance->AddSymbolPath(fs->Get()))
	{
		Prompt("Input Error", CtrlImg::error(), "The selected path was already added!", "OK");
	}
	
	this->mSymbolPathsList.SetVirtualCount(this->mSettingsInstance->GetSymbolPathCount());
	delete fs;
}

void CrySearchSettingsDialog::DeleteSymbolPathFromList()
{
	this->mSettingsInstance->DeleteSymbolPath(this->mSymbolPathsList.GetCursor());
	this->mSymbolPathsList.SetVirtualCount(this->mSettingsInstance->GetSymbolPathCount());
}

void CrySearchSettingsDialog::SettingsOk()
{
	// Check input values for possible errors.
	const int interval = StrInt(this->mAddressTableUpdaterIntervalEditField.GetText().ToString());
	if (this->mAddressTableUpdaterIntervalEditField.GetText().IsEmpty() || interval <= 0)
	{
		Prompt("Input Error", CtrlImg::error(), "The updater interval value is invalid.", "OK");
		return;
	}
	else
	{
		this->mSettingsInstance->SetAddressTableUpdateInterval(interval);
	}
	
	const int stackLimit = StrInt(this->mStackSnapshotLimitEdit.GetText().ToString());
	if (this->mStackSnapshotLimitEdit.GetText().IsEmpty() || stackLimit <= 0)
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
		this->mSettingsInstance->SetStackSnapshotLimit(stackLimit);
	}
	
	this->SaveSettings();
	this->Close();
}

void CrySearchSettingsDialog::SettingsCancel()
{
	this->Close();
}