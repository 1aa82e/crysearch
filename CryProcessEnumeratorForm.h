#ifndef _CrySearch_CryProcessEnumeratorForm_h_
#define _CrySearch_CryProcessEnumeratorForm_h_

#pragma warning(disable : 4005)

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#include "ProcessUtil.h"

// Represents a small area that can be clicked to begin a mouse dragging sequence.
class ProcessSelectionDragArea sealed : public ParentCtrl
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
class CryProcessEnumeratorForm sealed : public TopWindow
{
private:
	Label mInfoAboutDialog;
	EditField mSearchBox;
	Option mHideWindowLessProcesses;
	ProcessSelectionDragArea mDragArea;
	ArrayCtrl mProcessList;
	
	Button mOk;
	Button mCancel;
	Button mRefresh;
	Button mCreateProcess;
	
	void HideWindowsCheckedChanged();
	void SearchProcess();
	void CreateProcessButtonClicked();
	void OkButtonClicked();
	void CancelButtonClicked();
	void RefreshButtonWindowLess();
	void RefreshProcesses();
	void IdColumnHeaderClicked();
	void TitleColumnHeaderClicked();
	
	void DragFromCtrlCompleted(HWND hwnd);
	
	virtual bool Key(dword key, int count);
public:
	CryProcessEnumeratorForm();
	~CryProcessEnumeratorForm() { }
	
	typedef CryProcessEnumeratorForm CLASSNAME;

	Callback1<Win32ProcessInformation&> ProcessOpened;
};

#endif
