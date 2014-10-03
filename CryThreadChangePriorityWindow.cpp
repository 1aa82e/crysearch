#include "CryThreadChangePriorityWindow.h"
#include "GlobalDef.h"

CryThreadChangePriorityWindow::CryThreadChangePriorityWindow(const int threadId, const int current, const Image& icon) : CryDialogTemplate(icon)
{
	this->threadID = threadId;

	this->Title("Change Thread Priority").SetRect(0, 0, 200, 100);
	
	this->mOK <<= THISBACK(OkButton);
	this->mCancel <<= THISBACK(CancelButton);
	
	*this
		<< this->mCancel.SetLabel("Cancel").HSizePos(80, 65).BottomPos(5, 25)
		<< this->mOK.Ok().SetLabel("OK").HSizePos(140, 5).BottomPos(5, 25)
		<< this->priorDesc.SetLabel("Select Priority:").HSizePos(5, 5).TopPos(5, 20)
		<< this->priorSelect.Add("Lowest").Add("Below Normal").Add("Normal").Add("Idle").Add("Above Normal").Add("Highest")
			.Add("Realtime").HSizePos(5, 5).TopPos(30, 20)
	;
	
	this->priorSelect.SetIndex(current);
}

CryThreadChangePriorityWindow::~CryThreadChangePriorityWindow()
{
	
}

void CryThreadChangePriorityWindow::OkButton()
{
	int newPrior;
	
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
		default:
			// The compiler cannot know what value GetIndex() returns so it must be made assume that the value does not exceed the cases.
			__assume(0);
	}
	
	if (!CrySetThreadPriority(this->threadID, newPrior))
	{
		Prompt("Priority Error", CtrlImg::error(), "Failed to set the new priority level. Try refreshing the list and retry priority change.", "OK");
	}
	
	this->Close();
}

void CryThreadChangePriorityWindow::CancelButton()
{
	this->Close();
}