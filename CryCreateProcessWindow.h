#ifndef _CrySearch_CryCreateProcessWindow_h_
#define _CrySearch_CryCreateProcessWindow_h_

#include "CryDialogTemplate.h"
#include "ProcessUtil.h"

// Represents the dialog where a new process can be created with options.
class CryCreateProcessWindow : public CryDialogTemplate
{
private:
	Win32ProcessInformation* mProc;
	
	Label mProcessDescriptor;
	EditField mProcessPath;
	Label mArgumentsDescriptor;
	EditField mArguments;
	Option mCreateSuspended;
	Button mBrowseProcess;
	Button mCreate;
	Button mCancel;
	
	void BrowseForProcessButtonClicked();
	void CreateProcessButtonClicked();
	void CancelButtonClicked();
	
	typedef CryCreateProcessWindow CLASSNAME;
public:
	CryCreateProcessWindow(Win32ProcessInformation* const pProc);
	~CryCreateProcessWindow();
};

#endif