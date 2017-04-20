#include "SettingsFile.h"
#include "CrySearchForm.h"
#include "BackendGlobalDef.h"

// Link hotkeys to the correct callbacks according to the settings file.
void CrySearchForm::LinkHotkeysToActions()
{
	SettingsFile* const settings = SettingsFile::GetInstance();
	for (unsigned int i = 0; i < settings->GetHotkeyCount(); i++)
	{
		CrySearchHotKey& curKey = settings->GetHotkey(i);
		if (curKey.Description == "Refresh search results, changed value")
		{
			curKey.Action = THISBACK(HotkeyRefreshChanged);
		}
		else if (curKey.Description == "Refresh search results, unchanged value")
		{
			curKey.Action = THISBACK(HotkeyRefreshUnchanged);
		}
		else if (curKey.Description == "Refresh search results, increased value")
		{
			curKey.Action = THISBACK(HotkeyRefreshIncreased);
		}
		else if (curKey.Description == "Refresh search results, decreased value")
		{
			curKey.Action = THISBACK(HotkeyRefreshDecreased);
		}
		else if (curKey.Description == "Toggle Freeze/Thaw on all address table entries")
		{
			curKey.Action = THISBACK(HotkeyRefreshToggelFreezeAll);
		}
	}
}

// Checks whether hotkeys are pressed and if so, executes the corresponding actions.
void CrySearchForm::HotkeysProcedure()
{
	SettingsFile* tmpSettings = SettingsFile::GetInstance();
	const unsigned int count = tmpSettings->GetHotkeyCount();
	if (count > 0)
	{
		// Iterate saved hotkeys and configure parameters for its configured actions.
		for (unsigned int i = 0; i < count; ++i)
		{
			const CrySearchHotKey& curKey = tmpSettings->GetHotkey(i);
			
			// Check if the configured key is currently pressed.
			if (GetAsyncKeyState(curKey.Key) & 1)
			{
				// Execute the action for the hotkey.
				curKey.Action();
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------

// Executes the hotkey action for refreshing search results with changed value.
void CrySearchForm::HotkeyRefreshChanged()
{
	if (!mMemoryScanner->IsScanRunning() && mMemoryScanner->GetScanResultCount() > 0)
	{
		GlobalScanParameter->GlobalScanType = SCANTYPE_CHANGED;
		this->StartNextScanHotkey();
	}
}

// Executes the hotkey action for refreshing search results with unchanged value.
void CrySearchForm::HotkeyRefreshUnchanged()
{
	if (!mMemoryScanner->IsScanRunning() && mMemoryScanner->GetScanResultCount() > 0)
	{
		GlobalScanParameter->GlobalScanType = SCANTYPE_UNCHANGED;
		this->StartNextScanHotkey();
	}
}

// Executes the hotkey action for refreshing search results with increased value.
void CrySearchForm::HotkeyRefreshIncreased()
{
	if (!mMemoryScanner->IsScanRunning() && mMemoryScanner->GetScanResultCount() > 0)
	{
		GlobalScanParameter->GlobalScanType = SCANTYPE_INCREASED;
		this->StartNextScanHotkey();
	}
}

// Executes the hotkey action for refreshing search results with decreased value.
void CrySearchForm::HotkeyRefreshDecreased()
{
	if (!mMemoryScanner->IsScanRunning() && mMemoryScanner->GetScanResultCount() > 0)
	{
		GlobalScanParameter->GlobalScanType = SCANTYPE_DECREASED;
		this->StartNextScanHotkey();
	}
}

// Executes the hotkey action for toggling freeze/thaw on all address table entries.
void CrySearchForm::HotkeyRefreshToggelFreezeAll()
{
	const int aCount = loadedTable.GetCount();
	for (int a = 0; a < aCount; ++a)
	{
		loadedTable[a]->Frozen = !loadedTable[a]->Frozen;
	}
}