#ifndef _CrySearch_CryProcessEnumeratorForm_h_
#define _CrySearch_CryProcessEnumeratorForm_h_

#pragma warning(disable : 4005)

#include "ProcessUtil.h"
#include "CryDialogTemplate.h"
#include "CrySearchArrayCtrl.h"

// Represents a small area that can be clicked to begin a mouse dragging sequence.
class ProcessSelectionDragArea : public ParentCtrl
{
private:
	bool mIsDragging;
	Point dragThreshold;
	HCURSOR dragCursor;
	HCURSOR prevCursor;

	virtual void Paint(Draw& draw)
	{
		draw.DrawImage(0, 0, 16, 16, CtrlImg::plus());
	}
	
	virtual void LeftDown(Point p, dword keyflags);
	virtual void MouseMove(Point p, dword keyflags);
	virtual void LeftUp(Point p, dword keyflags);
	
	typedef ProcessSelectionDragArea CLASSNAME;
public:
	ProcessSelectionDragArea();	
	~ProcessSelectionDragArea() { }
	
	Callback1<HWND> DragCompleted;
};

// The form where the user selects the process to open in CrySearch.
class CryProcessEnumeratorForm : public CryDialogTemplate
{
private:
	volatile Atomic mCompletionCounter;
	int mThreadCount;
	Win32ProcessInformation tmpProc;
	
	Label mInfoAboutDialog;
	EditField mSearchBox;
	Option mHideWindowLessProcesses;
	ProcessSelectionDragArea mDragArea;
	CrySearchArrayCtrl mProcessList;
	
	Button mOk;
	Button mCancel;
	Button mRefresh;
	Button mCreateProcess;
	
	void HideWindowsCheckedChanged();
	void SearchProcess();
	void CreateProcessButtonClicked();
	void OkButtonClicked();
	void CancelButtonClicked();
	void RefreshProcesses(bool less);
	void IdColumnHeaderClicked();
	void TitleColumnHeaderClicked();
	
	void DragFromCtrlCompleted(HWND hwnd);
	void ProcessWindowIconAsync(Win32ProcessInformation pProcess, bool less);
	void IconProcesWaitCompleted(HICON hIcon, Win32ProcessInformation pProcess, bool less);
	void IconProcesWaitCompletedThreadSafe(HICON hIcon, Win32ProcessInformation pProcess, bool less);
	void AddToProcessListMoreLess(HICON hIcon, const Win32ProcessInformation& proc, bool less);
	
	Callback3<HICON, Win32ProcessInformation, bool> IconWaitCompleted;
	
	virtual void Close();
	
	typedef CryProcessEnumeratorForm CLASSNAME;
public:
	CryProcessEnumeratorForm(const Image& icon);
	~CryProcessEnumeratorForm() { }
	
	Win32ProcessInformation* const GetSelectedProcess();
	CryProcessEnumeratorForm* const GetPtr() const;
};

#endif
