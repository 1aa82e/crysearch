#ifndef _CrySearch_CryChangeRecordDialog_h_
#define _CrySearch_CryChangeRecordDialog_h_

#pragma warning(disable : 4005)

#include "GlobalDef.h"
#include "AddressTable.h"
#include "UIUtilities.h"
#include "CryDialogTemplate.h"

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
	
	void CancelDialog();
	void DialogOkay();
	
	void ValueModeHexOptionChanged();
	void BlockSizeSelected();
	
	typedef CryChangeRecordDialog CLASSNAME;
public:
	CryChangeRecordDialog(AddressTable& addrTable, const int row, ChangeRecordDialogMode mode);
	~CryChangeRecordDialog();
};

#endif
