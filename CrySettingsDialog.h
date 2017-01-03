#ifndef _CrySearch_CrySettingsDialog_h_
#define _CrySearch_CrySettingsDialog_h_

#include <CtrlLib/CtrlLib.h>

#include "BackendGlobalDef.h"
#include "CrySearchArrayCtrl.h"

using namespace Upp;

class CrySearchSettingsDialog : public TopWindow
{
private:
	bool mStartCheckedExtensionState;
	SettingsFile* mSettingsInstance;
	
	// Dialog main Ctrls
	TabCtrl mainTabCtrl;
	ParentCtrl mScanningTab;
	ParentCtrl mInternalsTab;
	ParentCtrl mDebuggerTab;
	ParentCtrl mHotkeysTab;
	ParentCtrl mAdvancedTab;
	Button mOk;
	Button mCancel;
	
	// Scanning tab
	Option fastScanByDefault;
	
	LabelBox mScanProtectionTypes;
	Option scanWritable;
	Option scanExecutable;
	Option scanCopyOnWrite;
	
	LabelBox mScanTypes;
	Option memPrivate;
	Option memImage;
	Option memMapped;
	
	LabelBox mScanThreadProperties;
	Label scanningThreadPriorityLabel;
	DropList scanningThreadPriority;
	
	Option mCrySearchInReadOnlyMode;
	
	// Internals tab
	LabelBox mAddressTableUpdaterIntervalBox;
	Label mAddressTableUpdaterIntervalDescription;
	EditField mAddressTableUpdaterIntervalEditField;
	LabelBox mRoutinesBox;
	Label mOpenProcRoutineSelectorLabel;
	DropList mOpenProcRoutineSelector;
	Label mReadMemoryProcRoutineSelectorLabel;
	DropList mReadMemoryProcRoutineSelector;
	Label mWriteMemoryProcRoutineSelectorLabel;
	DropList mWriteMemoryProcRoutineSelector;
	Label mProtectMemoryProcRoutineSelectorLabel;
	DropList mProtectMemoryProcRoutineSelector;
	Option mRegisterFileExtensionWithCrySearch;
	LabelBox mInjectionBox;
	Label mInjectionMethodDescriptor;
	DropList mInjectionMethod;
	
	// Debugger tab
	Label mStackSnapshotLimitDescriptor;
	EditField mStackSnapshotLimitEdit;
	Option dbgAttemptHidePeb;
	Option dbgInvadeProcess;
	Label mSymbolPathsDescriptor;
	CrySearchArrayCtrl mSymbolPathsList;
	Button mBrowseSymbolPath;
	Option dbgCatchAllExceptions;
	
	// Hotkeys tab
	Option mHotkeysOption;
	Button mAddHotkey;
	CrySearchArrayCtrl mHotkeysList;
	
	// Advanced tab
	Option mHideNonWow64ModulesInX64;
	Option mSignatureDefaultMasking;
	
	void LoadSettings();
	void SaveSettings();
	
	void InvadeProcessEnablerChanged();
	void AddSymbolPathToList();
	void DeleteSymbolPathFromList();
	void AddHotkeyToList();
	void EditHotkeyFromList();
	void HotkeyEnablerChanged();
	void DeleteHotkeyFromList();
	void WhenRightClickHotkeyList(Bar& pBar);
	void WhenRightClickSymbolPathList(Bar& pBar);
	
	void SettingsOk();
	void SettingsCancel();
public:
	CrySearchSettingsDialog();
	
	typedef CrySearchSettingsDialog CLASSNAME;
};

#endif
