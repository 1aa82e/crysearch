#include "CryChangeRecordOffsetsWindow.h"
#include "ImlProvider.h"
#include "SettingsFile.h"
#include "UIUtilities.h"

// CryChangeRecordOffsetsWindow default constructor.
CryChangeRecordOffsetsWindow::CryChangeRecordOffsetsWindow(Vector<int>* pOffsets) : CryDialogTemplate(CrySearchIml::ChangeRecordIcon())
{
	this->Title("Change Offsets").SetRect(0, 0, 250, 160);
	
	this->mCancel <<= THISBACK(CancelDialog);
	this->mOK <<= THISBACK(DialogOkay);
	this->mAddNextOffset <<= THISBACK(AddNextOffsetToList);
	
	this->mOffsets.WhenBar = THISBACK(PopulateOffsetsMenuBar);
	this->mOffsets.CryAddColumn("Offset");
	this->mNextOffset.SetData(0);
	
	*this
		<< this->mNextOffsetDesc.SetLabel("Offset:").LeftPos(5, 60).TopPos(5, 25)
		<< this->mNextOffset.Min(0).LeftPos(70, 50).TopPos(5, 25)
		<< this->mAddNextOffset.SetLabel("Add").LeftPos(125, 50).TopPos(5, 25)
		<< this->mOffsets.HSizePos(5, 5).VSizePos(35, 35)
		<< this->mCancel.SetLabel("Cancel").RightPos(7, 70).BottomPos(5, 25)
		<< this->mOK.Ok().SetLabel("OK").RightPos(80, 70).BottomPos(5, 25)
	;
	
	// Load the existing offsets.
	this->mTempOffsets = pOffsets;
	for (int o : *pOffsets)
	{
		this->mOffsets.Add(SettingsFile::GetInstance()->GetViewOffsetsInHexadecimal() ? FormatHexadecimalIntSpecial(o) : FormatIntSpecial(o));
	}
}

// CryChangeRecordOffsetsWindow default destructor.
CryChangeRecordOffsetsWindow::~CryChangeRecordOffsetsWindow()
{
	
}

// Populates the context menu for the offsets list.
void CryChangeRecordOffsetsWindow::PopulateOffsetsMenuBar(Bar& pBar)
{
	const int row = this->mOffsets.GetCursor();
	if (row >= 0 && this->mOffsets.GetCount() > 0)
	{
		pBar.Add("Delete", CrySearchIml::DeleteButton(), THISBACK(RemoveOffsetFromList));
		pBar.Add("Move Up", THISBACK(OffsetEntryMoveUp));
		pBar.Add("Move Down", THISBACK(OffsetEntryMoveDown));
	}
}

// Adds an offset to the list of offsets for this address table entry.
void CryChangeRecordOffsetsWindow::AddNextOffsetToList()
{
	// Only add the next offset if the number of offsets has not yet been exceeded.
	if (this->mOffsets.GetCount() > POINTER_ENTRY_MAX_NUMBER_OFFSETS)
	{
		Prompt("Input Error", CtrlImg::error(), "The maximum number of offsets was exceeded!", "OK");
		return;
	}
	
	// We can add the next offset.
	this->mOffsets.Add(SettingsFile::GetInstance()->GetViewOffsetsInHexadecimal() ? FormatHexadecimalIntSpecial((int)this->mNextOffset) : FormatIntSpecial((int)this->mNextOffset));
}

// Deletes the selected offset from the list.
void CryChangeRecordOffsetsWindow::RemoveOffsetFromList()
{
	this->mOffsets.Remove(this->mOffsets.GetCursor());
}

// Moves an offset up by one.
void CryChangeRecordOffsetsWindow::OffsetEntryMoveUp()
{
	this->mOffsets.SwapUp();
}

// Moves an offset down by one.
void CryChangeRecordOffsetsWindow::OffsetEntryMoveDown()
{
	this->mOffsets.SwapDown();
}

// Executed when the user cancels dialog input.
void CryChangeRecordOffsetsWindow::CancelDialog()
{
	// We do not save the offsets, discarding any changes.
	this->Close();
}

// Executed when the user accepts the dialog input.
void CryChangeRecordOffsetsWindow::DialogOkay()
{
	// Save the offsets to the loaded table entry.
	this->mTempOffsets->Clear();
	const int count = this->mOffsets.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const String& val = this->mOffsets.Get(i, 0);
		this->mTempOffsets->Add(SettingsFile::GetInstance()->GetViewOffsetsInHexadecimal() ? ScanInt(val, NULL, 16) : ScanInt(val, NULL, 10));
	}
	
	this->Close();
}