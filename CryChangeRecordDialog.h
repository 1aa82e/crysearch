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
	CDRM_MANUALNEW,
	CRDM_DESCRIPTION,
	CRDM_ADDRESS,
	CRDM_VALUE,
	CRDM_TYPE
};

// The record change dialog class definition.
class CryChangeRecordDialog sealed : public CryDialogTemplate
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
	Option mUnicodeString;
	Option mValueIsHex;
	
	void CancelDialog();
	void DialogOkay();
	
	void ValueModeHexOptionChanged();
	void BlockSizeSelected();
	
	typedef CryChangeRecordDialog CLASSNAME;
public:
#ifdef _WIN64
	CryChangeRecordDialog(AddressTable& addrTable, const __int64 address, const String& type, ChangeRecordDialogMode mode);
#else
	CryChangeRecordDialog(AddressTable& addrTable, const int address, const String& type, ChangeRecordDialogMode mode);
#endif
	~CryChangeRecordDialog();
};

#endif
