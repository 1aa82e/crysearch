#include "CryProcessEnumeratorForm.h"
#include "CryCreateProcessWindow.h"
#include "ImlProvider.h"
#include "HIconToImage.h"
#include "BackendGlobalDef.h"

// Global variable indicates whether the process window was closed or not.
bool ProcWndClosed;

// Dragging area control code.
ProcessSelectionDragArea::ProcessSelectionDragArea()
{
	// Get system dragging threshold values.
	this->dragThreshold.x = GetSystemMetrics(SM_CXDRAG);
	this->dragThreshold.y = GetSystemMetrics(SM_CYDRAG);
	this->mIsDragging = false;
	this->dragCursor = LoadCursor(NULL, IDC_CROSS);
	this->prevCursor = NULL;
}

// Drag-drop event for when the mouse button is pressed.
void ProcessSelectionDragArea::LeftDown(Point p, dword keyflags)
{
	this->mIsDragging = true;
	this->prevCursor = GetCursor();
	SetCursor(this->dragCursor);
}

// Drag-drop event for when the mouse is moved.
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

// The drag-drop event when mouse button is released.
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
		
		// Release capture for this control.
		this->ReleaseCapture();
		this->mIsDragging = false;
		SetCursor(this->prevCursor);
		
		// Fire event for drag completed.
		this->DragCompleted(newWnd);
	}
}

// Default CryProcessEnumeratorForm constructor.
CryProcessEnumeratorForm::CryProcessEnumeratorForm(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Select Process").SetRect(0, 0, 340, 360);
	
	this->mOk <<= THISBACK(OkButtonClicked);
	this->mCancel <<= THISBACK(CancelButtonClicked);
	this->mRefresh <<= THISBACK(HideWindowsCheckedChanged);
	this->mCreateProcess <<= THISBACK(CreateProcessButtonClicked);
	
	this->mSearchBox.WhenAction = THISBACK(SearchProcess);
	
	this->mProcessList.CryAddColumn("", 10).SetDisplay(ImageDisplay());
	ArrayCtrl::Column& col0 = this->mProcessList.CryAddColumn("PID", 25);
	ArrayCtrl::Column& col1 = this->mProcessList.CryAddColumn("Title", 65);
	this->mProcessList.WhenLeftDouble = THISBACK(OkButtonClicked);
	
	col0.HeaderTab().WhenAction = THISBACK(IdColumnHeaderClicked);
	col1.HeaderTab().WhenAction = THISBACK(TitleColumnHeaderClicked);
	
	this->mHideWindowLessProcesses.WhenAction = THISBACK(HideWindowsCheckedChanged);
	this->mDragArea.DragCompleted = THISBACK(DragFromCtrlCompleted);
	
	*this
		<< this->mInfoAboutDialog.SetText("Search for process:").HSizePos(5, 5).TopPos(5, 25)
		<< this->mSearchBox.HSizePos(150, 5).TopPos(5, 25)
		<< this->mHideWindowLessProcesses.SetLabel("Hide processes with no window").HSizePos(5, 30).TopPos(30, 25)
		<< this->mDragArea.RightPos(5, 20).TopPos(35, 20)
		<< this->mProcessList.HSizePos(5, 5).VSizePos(60, 35)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(70, 60).BottomPos(5, 25)
		<< this->mRefresh.SetLabel("Refresh").RightPos(135, 65).BottomPos(5, 25)
		<< this->mCreateProcess.SetLabel("Create Process").LeftPos(5, 130).BottomPos(5, 25)
	;
	
	ProcWndClosed = false;
	this->tmpProc.UserInterfaceFlags = 0;
	this->tmpProc.ProcessId = 0;
	this->mCompletionCounter = 0;
	this->mThreadCount = 0;
	this->IconWaitCompleted = THISBACK(IconProcesWaitCompleted);
	this->RefreshProcesses(false);
}

// Default CryProcessEnumeratorForm destructor.
CryProcessEnumeratorForm::~CryProcessEnumeratorForm()
{
	
}

// Executed when the user clicks the column header of process id.
void CryProcessEnumeratorForm::IdColumnHeaderClicked()
{
	this->mProcessList.SetSortColumn(1);
}

// Executed when the user clicks the column header of process name.
void CryProcessEnumeratorForm::TitleColumnHeaderClicked()
{
	this->mProcessList.SetSortColumn(2);
}

// Executed when the window filter selection changes.
void CryProcessEnumeratorForm::HideWindowsCheckedChanged()
{
	this->RefreshProcesses(this->mHideWindowLessProcesses);
}

// Executed when the user lets go of the mouse in a drag-drop session.
void CryProcessEnumeratorForm::DragFromCtrlCompleted(HWND hwnd)
{
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	tmpProc.ProcessId = pid;
	
	this->AcceptBreak(10);
}

// Opens an input dialog to create a new process from a command line string.
void CryProcessEnumeratorForm::CreateProcessButtonClicked()
{
	CryCreateProcessWindow* ccpw = new CryCreateProcessWindow(&this->tmpProc);
	if (ccpw->Execute() == 10)
	{
		this->AcceptBreak(10);
	}
	delete ccpw;
}

// Refreshes the process and window list by scanning for processes.
void CryProcessEnumeratorForm::SearchProcess()
{
	this->RefreshProcesses(this->mHideWindowLessProcesses);
}

// Retrieves the process that is currently selected.
Win32ProcessInformation* const CryProcessEnumeratorForm::GetSelectedProcess()
{
	return &this->tmpProc;
}

// Accepts the process selection dialog using the selected process as input.
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

// Closes the process selection window.
void CryProcessEnumeratorForm::CancelButtonClicked()
{
	this->Close();
}

// Refreshes the processes and windows in the list.
void CryProcessEnumeratorForm::RefreshProcesses(bool less)
{
	// Clear the user interface and retrieve process list.
	this->mProcessList.Clear();
	Vector<Win32ProcessInformation> mProcesses;
	EnumerateProcesses(mProcesses);
	
	// Disable search box until the asynchronous operation completed.
	this->mSearchBox.SetEditable(false);
	this->mThreadCount = mProcesses.GetCount();
	this->mCompletionCounter = 0;
	
	// Loop processes.
	for (int i = 0; i < this->mThreadCount; ++i)
	{
		// Start callbacks to asynchronously retrieve icons.
		this->mIconThread.Start(PTEBACK2(ProcessWindowIconAsync, mProcesses[i], less));
	}
}

void CryProcessEnumeratorForm::ProcessWindowIconAsync(Win32ProcessInformation pProcess, bool less)
{
	this->IconWaitCompleted(hIconForPID(pProcess.ProcessId), pProcess, less);
}

void CryProcessEnumeratorForm::IconProcesWaitCompleted(HICON hIcon, Win32ProcessInformation pProcess, bool less)
{
	PostCallback(THISBACK3(IconProcesWaitCompletedThreadSafe, hIcon, pProcess, less));
}

void CryProcessEnumeratorForm::IconProcesWaitCompletedThreadSafe(HICON hIcon, Win32ProcessInformation pProcess, bool less)
{
	String lowered = ToLower(this->mSearchBox.GetText().ToString());
	if (lowered.IsEmpty())
	{
		this->AddToProcessListMoreLess(hIcon, pProcess, less);
	}
	else
	{
		if (ToLower(pProcess.ExeTitle).StartsWith(lowered))
		{
			this->AddToProcessListMoreLess(hIcon, pProcess, less);
		}
	}
	
	// If the completion token is set this thread should reset user input state.
	if (AtomicInc(this->mCompletionCounter) == this->mThreadCount)
	{
		this->mSearchBox.SetEditable(true);
	}
}

// Adds filtered input of processes and windows to the process list.
void CryProcessEnumeratorForm::AddToProcessListMoreLess(HICON hIcon, const Win32ProcessInformation& proc, bool less)
{
	// For unknown reasons, the process may sometimes be added more than once. The solution is lazy but easy.
	if (this->mProcessList.Find(proc.ProcessId, 1) != -1)
	{
		return;
	}
	
	// The process was not yet found in the list. Add it to the list.
	if (less)
	{
		if (hIcon)
		{
			this->mProcessList.Add(CreateImageFromHICON(hIcon), proc.ProcessId, proc.ExeTitle);
		}
	}
	else
	{
		this->mProcessList.Add(CreateImageFromHICON(hIcon), proc.ProcessId, proc.ExeTitle);
	}
}

// Override of the close function to block new callbacks.
void CryProcessEnumeratorForm::Close()
{
	ProcWndClosed = true;
	WaitCursor waitcursor;
	this->mIconThread.Wait();
	CryDialogTemplate::Close();
}