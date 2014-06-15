#include "CryProcessEnumeratorForm.h"
#include "ImlProvider.h"
#include "HIconToImage.h"

// Dragging area control code.
ProcessSelectionDragArea::ProcessSelectionDragArea()
{
	// Get system dragging threshold values.
	this->dragThreshold;
	this->dragThreshold.x = GetSystemMetrics(SM_CXDRAG);
	this->dragThreshold.y = GetSystemMetrics(SM_CYDRAG);
	this->mIsDragging = false;
	this->dragCursor = LoadCursor(NULL, IDC_CROSS);
}

void ProcessSelectionDragArea::LeftDown(Point p, dword keyflags)
{
	this->mIsDragging = true;
	this->prevCursor = GetCursor();
	SetCursor(this->dragCursor);
}

void ProcessSelectionDragArea::MouseMove(Point p, dword keyflags)
{
	if (this->mIsDragging)
	{
		// The parent mouse move events reset the cursor, so keep resetting it in here until the dragging is complete.
		SetCursor(this->dragCursor);
		
		if (p.x >= this->dragThreshold.x || p.y >= this->dragThreshold.y)
		{
			this->SetCapture();
		}
	}
}

void ProcessSelectionDragArea::LeftUp(Point p, dword keyflags)
{
	if (this->mIsDragging && this->HasCapture())
	{
		// Drag was completed, retrieve HWND of the window that ended the drag.
		POINT* winp = (POINT*)&p;
		ClientToScreen(this->GetParent()->GetHWND(), winp);
		Rect thisCtrl = this->GetRect();
		winp->x += thisCtrl.left;
		winp->y += thisCtrl.top;
		HWND newWnd = WindowFromPoint(*winp);
		
		this->ReleaseCapture();
		this->mIsDragging = false;
		SetCursor(this->prevCursor);
		
		this->DragCompleted(newWnd);
	}
}

CryProcessEnumeratorForm::CryProcessEnumeratorForm(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Select Process").SetRect(0, 0, 340, 360);
	
	this->mOk <<= THISBACK(OkButtonClicked);
	this->mCancel <<= THISBACK(CancelButtonClicked);
	this->mRefresh <<= THISBACK(HideWindowsCheckedChanged);
	this->mCreateProcess <<= THISBACK(CreateProcessButtonClicked);
	
	this->mSearchBox.WhenAction = THISBACK(SearchProcess);
	
	this->mProcessList.AddColumn("", 10).SetDisplay(ImageDisplay());
	ArrayCtrl::Column& col0 = this->mProcessList.AddColumn("PID", 25);
	ArrayCtrl::Column& col1 = this->mProcessList.AddColumn("Title", 65);
	this->mProcessList.WhenLeftDouble = THISBACK(OkButtonClicked);
	
	col0.HeaderTab().WhenAction = THISBACK(IdColumnHeaderClicked);
	col1.HeaderTab().WhenAction = THISBACK(TitleColumnHeaderClicked);
	
	this->mHideWindowLessProcesses.WhenAction = THISBACK(HideWindowsCheckedChanged);
	this->mDragArea.DragCompleted = THISBACK(DragFromCtrlCompleted);
	
	*this
		<< this->mInfoAboutDialog.SetText("Search for process:").HSizePos(5, 5).TopPos(5, 20)
		<< this->mSearchBox.HSizePos(150, 5).TopPos(5, 20)
		<< this->mHideWindowLessProcesses.SetLabel("Hide processes with no window").HSizePos(5, 30).TopPos(30, 25)
		<< this->mDragArea.RightPos(5, 20).TopPos(35, 20)
		<< this->mProcessList.HSizePos(5, 5).VSizePos(60, 35)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(70, 60).BottomPos(5, 25)
		<< this->mRefresh.SetLabel("Refresh").RightPos(135, 65).BottomPos(5, 25)
		<< this->mCreateProcess.SetLabel("Create Process").LeftPos(5, 130).BottomPos(5, 25)
	;
		
	this->RefreshProcesses();
}

void CryProcessEnumeratorForm::IdColumnHeaderClicked()
{
	this->mProcessList.SetSortColumn(1);
}

void CryProcessEnumeratorForm::TitleColumnHeaderClicked()
{
	this->mProcessList.SetSortColumn(2);
}

void CryProcessEnumeratorForm::HideWindowsCheckedChanged()
{
	if (this->mHideWindowLessProcesses)
	{
		this->RefreshButtonWindowLess();
	}
	else
	{
		this->RefreshProcesses();
	}
}

void CryProcessEnumeratorForm::DragFromCtrlCompleted(HWND hwnd)
{
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	tmpProc.ProcessId = pid;
	
	this->AcceptBreak(10);
}

void CryProcessEnumeratorForm::CreateProcessButtonClicked()
{
	FileSel* fs = new FileSel();
	fs->Types("Executable files\t*.exe");
	
	if (fs->ExecuteOpen("Select executable file..."))
	{
		// Set process identifier to -1 to indicate that the process ID should not be used.
		tmpProc.ProcessId = -1;
		tmpProc.ExeTitle = fs->Get();
		
		delete fs;
		this->AcceptBreak(10);
	}
	else
	{
		delete fs;
	}
}

void CryProcessEnumeratorForm::SearchProcess()
{
	if (this->mHideWindowLessProcesses)
	{
		this->RefreshButtonWindowLess();
	}
	else
	{
		this->RefreshProcesses();
	}
	
	if (this->mSearchBox.GetText().IsEmpty())
	{
		return;
	}
	else
	{
		String lowered = ToLower(this->mSearchBox.GetText().ToString());
		for (int i = 0; i < this->mProcessList.GetCount(); ++i)
		{
			// Remove elements that do not match the search input.
			if (!(ToLower(this->mProcessList.Get(i, 2).ToString()).StartsWith(lowered)))
			{
				this->mProcessList.Remove(i--);
			}
		}
		
		// Select first row for fast return press. Enables fast opening of processes when typing the entire process name instead of moving the mouse.
		if (this->mProcessList.GetCount() > 0)
		{
			this->mProcessList.SetCursor(0);
		}
	}
}

Win32ProcessInformation* const CryProcessEnumeratorForm::GetSelectedProcess()
{
	return &this->tmpProc;
}

void CryProcessEnumeratorForm::OkButtonClicked()
{
	const int row = this->mProcessList.GetCursor();
	if (row >= 0 && this->mProcessList.GetCount() > 0)
	{
		tmpProc.ProcessId = this->mProcessList.Get(row, 1);
		tmpProc.ExeTitle = this->mProcessList.Get(row, 2);
		
		this->AcceptBreak(10);
	}
	else
	{
		Prompt("Input Error", CtrlImg::error(), "Please select a process to attach to!", "OK");
	}
}

void CryProcessEnumeratorForm::CancelButtonClicked()
{
	this->Close();
}

void CryProcessEnumeratorForm::RefreshButtonWindowLess()
{
	this->mProcessList.Clear();
	Vector<Win32ProcessInformation> mProcesses;
	EnumerateProcesses(mProcesses);
	
	for (int i = 0; i < mProcesses.GetCount(); ++i)
	{
		// Retrieve windows associated to the process and get its icon.
		HICON ico = hIconForPID(mProcesses[i].ProcessId);
		if (ico)
		{
			// Only add to list if window icon was found.
			this->mProcessList.Add(CreateImageFromHICON(ico), mProcesses[i].ProcessId, mProcesses[i].ExeTitle);
		}
	}
}

void CryProcessEnumeratorForm::RefreshProcesses()
{
	this->mProcessList.Clear();
	Vector<Win32ProcessInformation> mProcesses;
	EnumerateProcesses(mProcesses);
	
	for (int i = 0; i < mProcesses.GetCount(); ++i)
	{
		// Retrieve windows associated to the process and get its icon.
		HICON ico = hIconForPID(mProcesses[i].ProcessId);
		this->mProcessList.Add(CreateImageFromHICON(ico), mProcesses[i].ProcessId, mProcesses[i].ExeTitle);
	}
}