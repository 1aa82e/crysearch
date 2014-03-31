#ifndef _CrySearch_CryDumpModuleSectionWindow_h_
#define _CrySearch_CryDumpModuleSectionWindow_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "PortableExecutable.h"

// Represents the window that allows users to dump specific sections of a loaded module.
class CryDumpModuleSectionWindow sealed : public TopWindow
{
private:
	Win32ModuleInformation* mModuleInfo;
	Vector<Win32PESectionInformation> imageSections;
	
	ArrayCtrl mSectionsList;
	Button mDumpButton;
	Button mCancelButton;

	void CancelAndCloseDialog();
	void DumpSelectedSection();
	
	virtual bool Key(dword key, int count);
	
	typedef CryDumpModuleSectionWindow CLASSNAME;
public:
	CryDumpModuleSectionWindow(const int modListIndex);
	~CryDumpModuleSectionWindow();	
};

#endif
