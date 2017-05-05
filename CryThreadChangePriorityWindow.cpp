#include "CryThreadChangePriorityWindow.h"
#include "BackendGlobalDef.h"

// CryThreadChangePriorityWindow default constructor.
CryThreadChangePriorityWindow::CryThreadChangePriorityWindow(const int threadId, const int current, const Image& icon) : CryDialogTemplate(icon)
{
	this->threadID = threadId;

	this->Title("Change Thread Priority").SetRect(0, 0, 200, 100);
	
	this->mOK <<= THISBACK(OkButton);
	this->mCancel <<= THISBACK(CancelButton);
	
	*this
		<< this->mCancel.SetLabel("Cancel").HSizePos(60, 75).BottomPos(5, 25)
		<< this->mOK.Ok().SetLabel("OK").HSizePos(130, 5).BottomPos(5, 25)
		<< this->priorDesc.SetLabel("Select Priority:").HSizePos(5, 5).TopPos(5, 25)
		<< this->priorSelect.Add("Lowest").Add("Below Normal").Add("Normal").Add("Idle").Add("Above Normal").Add("Highest")
			.Add("Realtime").HSizePos(5, 5).TopPos(30, 25)
	;
	
	this->priorSelect.SetIndex(current);
}

// CryThreadChangePriorityWindow default destructor.
CryThreadChangePriorityWindow::~CryThreadChangePriorityWindow()
{
	
}

// Executed when the user accepts the dialog input.
void CryThreadChangePriorityWindow::OkButton()
{
	int newPrior;
	
	// Assign the correct thread priority.
	switch (this->priorSelect.GetIndex())
	{
		case 0:
			newPrior = THREAD_PRIORITY_LOWEST;
			break;
		case 1:
			newPrior = THREAD_PRIORITY_BELOW_NORMAL;
			break;
		case 2:
			newPrior = THREAD_PRIORITY_NORMAL;
			break;
		case 3:
			newPrior = THREAD_PRIORITY_IDLE;
			break;
		case 4:
			newPrior = THREAD_PRIORITY_ABOVE_NORMAL;
			break;
		case 5:
			newPrior = THREAD_PRIORITY_HIGHEST;
			break;
		case 6:
			newPrior = THREAD_PRIORITY_TIME_CRITICAL;
			break;
	}
	
	// Change the thread priority of the selected thread.
	if (!CrySetThreadPriority(this->threadID, newPrior))
	{
		Prompt("Priority Error", CtrlImg::error(), "Failed to set the new priority level. Try refreshing the list and retry priority change.", "OK");
	}
	
	this->Close();
}

// Executed when the user closes the dialog without accepting the input.
void CryThreadChangePriorityWindow::CancelButton()
{
	this->Close();
}