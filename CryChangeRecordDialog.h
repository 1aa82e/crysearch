#ifndef _CrySearch_CryChangeRecordDialog_h_
#define _CrySearch_CryChangeRecordDialog_h_

#include "UIUtilities.h"
#include "CryChangeRecordOffsetsWindow.h"

// Defines the mode the dialog should be opened. 4 different ways to edit a record in the addresstable.
enum ChangeRecordDialogMode
{
	CRDM_MANUALNEW,
	CRDM_DESCRIPTION,
	CRDM_ADDRESS,
	CRDM_VALUE,
	CRDM_TYPE
};

// The record change dialog class definition.
class CryChangeRecordDialog : public CryDialogTemplate
{
private:
	ChangeRecordDialogMode mMode;
	AddressTableEntry* mLoadedEntry;
	AddressTable* mLoadedTable;
	const Vector<int>* mRowArray;
	Vector<int> mThisEntryOffsets;
	
	Button mCancel;
	Button mOk;
	Label mFieldDescription;
	EditField mFieldValue;
	DropList mTypeSelector;
	Label mTypeLengthDescription;
	EditIntNotNull mTypeLength;
	Option mUnicodeString;
	Option mValueIsHex;
	Label mSecondFieldDescription;
	Option mIsPointer;
	Button mOffsetsWindow;
	
	void CancelDialog();
	void AlterSearchResult(const SIZE_T address, const int size);
	void DialogOkay();
	void OffsetsWindowClicked();
	void IsPointerCheckedChanged();
	void ValueModeHexOptionChanged();
	void BlockSizeSelected();
	
	typedef CryChangeRecordDialog CLASSNAME;
public:
	CryChangeRecordDialog(AddressTable& addrTable, const Vector<int>& rows, ChangeRecordDialogMode mode);
	~CryChangeRecordDialog();
};

#endif
