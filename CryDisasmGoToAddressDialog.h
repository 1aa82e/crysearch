#ifndef _CrySearch_CryDisasmGoToAddressDialog_h_
#define _CrySearch_CryDisasmGoToAddressDialog_h_

#include "CryDialogTemplate.h"

// Small dialog that is opened when the 'Go to address' context menu action is chosen from the disassembly view.
class CryDisasmGoToAddressDialog : public CryDialogTemplate
{
private:
	LONG_PTR* addrPtr;
	
	Label mAddressDesc;
	EditField mAddressInput;
	Button mOk;
	Button mCancel;
	
	void OkButtonClicked();
	void CancelButtonClicked();
	
	typedef CryDisasmGoToAddressDialog CLASSNAME;
public:
	CryDisasmGoToAddressDialog(LONG_PTR* addr);	
	~CryDisasmGoToAddressDialog();
};

#endif