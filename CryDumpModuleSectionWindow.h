#ifndef _CrySearch_CryDumpModuleSectionWindow_h_
#define _CrySearch_CryDumpModuleSectionWindow_h_

#include "PortableExecutable.h"
#include "CryDialogTemplate.h"

// Represents the window that allows users to dump specific sections of a loaded module.
class CryDumpModuleSectionWindow sealed : public CryDialogTemplate
{
private:
	Win32ModuleInformation* mModuleInfo;
	Vector<Win32PESectionInformation> imageSections;
	
	Label mSectionCount;
	ArrayCtrl mSectionsList;
	Button mDumpButton;
	Button mCancelButton;

	void CancelAndCloseDialog();
	void DumpSelectedSection();
	
	typedef CryDumpModuleSectionWindow CLASSNAME;
public:
	CryDumpModuleSectionWindow(const int modListIndex);
	~CryDumpModuleSectionWindow();	
};

#endif
