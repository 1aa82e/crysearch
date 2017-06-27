#ifndef _CrySearch_CryChangeRecordOffsetsWindow_h_
#define _CrySearch_CryChangeRecordOffsetsWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "CryDialogTemplate.h"
#include "AddressTable.h"
#include "CrySearchArrayCtrl.h"

// Defines the maximum number of offsets a pointer in CrySearch can have.
#define POINTER_ENTRY_MAX_NUMBER_OFFSETS	16

// Represents the pointer offsets window for an address table entry.
class CryChangeRecordOffsetsWindow : public CryDialogTemplate
{
private:
	Label mNextOffsetDesc;
	EditIntSpin mNextOffset;
	Button mAddNextOffset;
	CrySearchArrayCtrl mOffsets;
	Button mOK;
	Button mCancel;
	Vector<int>* mTempOffsets;
	
	void AddNextOffsetToList();
	void RemoveOffsetFromList();
	void OffsetEntryMoveUp();
	void OffsetEntryMoveDown();
	void CancelDialog();
	void DialogOkay();
	
	void PopulateOffsetsMenuBar(Bar& pBar);
	
	typedef CryChangeRecordOffsetsWindow CLASSNAME;
public:
	CryChangeRecordOffsetsWindow(Vector<int>* pOffsets);
	~CryChangeRecordOffsetsWindow();
};

#endif