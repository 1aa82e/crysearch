#include "CryCreateProcessWindow.h"
#include "ImlProvider.h"

CryCreateProcessWindow::CryCreateProcessWindow(Win32ProcessInformation* const pProc) : CryDialogTemplate(CrySearchIml::AttachToProcessMenu())
{
	this->mProc = pProc;
	this->Title("Create Process").SetRect(0, 0, 300, 120);
	
	this->mBrowseProcess <<= THISBACK(BrowseForProcessButtonClicked);
	this->mCreate <<= THISBACK(CreateProcessButtonClicked);
	this->mCancel <<= THISBACK(CancelButtonClicked);
	
	*this
		<< this->mProcessDescriptor.SetLabel("Path:").LeftPos(5, 75).TopPos(5, 25)
		<< this->mProcessPath.HSizePos(90, 5).TopPos(5, 25)
		<< this->mArgumentsDescriptor.SetLabel("Arguments:").LeftPos(5, 75).TopPos(35, 25)
		<< this->mArguments.HSizePos(90, 5).TopPos(35, 25)
		<< this->mCreateSuspended.SetLabel("Create suspended process").HSizePos(5, 5).TopPos(65, 25)
		<< this->mBrowseProcess.SetLabel("Browse").LeftPos(5, 90).BottomPos(5, 25)
		<< this->mCreate.Ok().SetLabel("Create Process").RightPos(70, 130).BottomPos(5, 25)
		<< this->mCancel.SetLabel("Cancel").RightPos(5, 60).BottomPos(5, 25)
	;
}

CryCreateProcessWindow::~CryCreateProcessWindow()
{
	
}

void CryCreateProcessWindow::BrowseForProcessButtonClicked()
{
	FileSel* fs = new FileSel();
	fs->Types("Executable files\t*.exe");
	
	// If a file was selected, put the path in the path edit field.
	if (fs->ExecuteOpen("Select executable file..."))
	{
		this->mProcessPath.SetText(fs->Get());
	}
	
	delete fs;
}

void CryCreateProcessWindow::CreateProcessButtonClicked()
{
	const String& path = this->mProcessPath.GetText().ToString();
	if (!path.IsEmpty())
	{
		// Set process identifier to -1 to indicate that the process ID should not be used.
		this->mProc->ProcessId = -1;
		this->mProc->ExeTitle = path;
		this->mProc->ProcessArguments = this->mArguments.GetText().ToString();
		
		// Set flags for process creation.
		if (this->mCreateSuspended)
		{
			this->mProc->UserInterfaceFlags |= CREATE_SUSPENDED;
		}
		
		this->AcceptBreak(10);
	}
	else
	{
		Prompt("Input Error", CtrlImg::error(), "Please enter a valid process path!", "OK");
	}
}

void CryCreateProcessWindow::CancelButtonClicked()
{
	this->Close();
}