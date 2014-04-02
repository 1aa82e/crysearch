#ifndef _CrySearch_CrySettingsDialog_h_
#define _CrySearch_CrySettingsDialog_h_

#pragma warning(disable : 4005)

#include <CtrlLib/CtrlLib.h>

#include "GlobalDef.h"

using namespace Upp;

class CrySearchSettingsDialog sealed : public TopWindow
{
private:
	bool mStartCheckedExtensionState;
	
	// Dialog main Ctrls
	TabCtrl mainTabCtrl;
	ParentCtrl mScanningTab;
	ParentCtrl mGeneralTab;
	ParentCtrl mDebuggerTab;
	ParentCtrl mHotkeysTab;
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
	
	// General tab
	LabelBox mAddressTableUpdaterIntervalBox;
	Label mAddressTableUpdaterIntervalDescription;
	EditField mAddressTableUpdaterIntervalEditField;
	LabelBox mRoutinesBox;
	Label mOpenProcRoutineSelectorLabel;
	DropList mOpenProcRoutineSelector;
	Option mRegisterFileExtensionWithCrySearch;
	
	// Debugger tab
	Label mStackSnapshotLimitDescriptor;
	EditField mStackSnapshotLimitEdit;
	Option dbgAttemptHidePeb;
	Option dbgInvadeProcess;
	Label mSymbolPathsDescriptor;
	ArrayCtrl mSymbolPathsList;
	Button mBrowseSymbolPath;
	
	// Hotkeys tab
	Option mHotkeysOption;
	Button mAddHotkey;
	ArrayCtrl mHotkeysList;
	
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
