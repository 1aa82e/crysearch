#include "CrySystemHandleAccessMaskWindow.h"
#include "HandlePermissions.h"

CrySystemHandleAccessMaskWindow::CrySystemHandleAccessMaskWindow(const String& type, const DWORD mask)
{
	this->Title("Access Mask").SetRect(0, 0, 300, 200);

	*this
		<< this->mAccessConstants.HSizePos(5, 5).VSizePos(5, 30)
		<< this->mClose.SetLabel("Close").RightPos(5, 60).BottomPos(5, 20)
	;
	
	this->mAccessConstants.AddColumn("Constant");
	this->mClose <<= THISBACK(FormClose);
	
	// Load mask dissection and visualize it.
	char** buf = NULL;
	DWORD intType = 0;
	if (strcmp(type.Begin(), "File") == 0 || strcmp(type.Begin(), "Directory") == 0)
	{
		buf = new char*[SAFE_BUFFER_SIZE_FILE];
		intType = HANDLE_ACCESS_TYPE_FILE;
	}
	else if (strcmp(type.Begin(), "Thread") == 0)
	{
		buf = new char*[SAFE_BUFFER_SIZE_THREAD];
		intType = HANDLE_ACCESS_TYPE_THREAD;
	}
	else if (strcmp(type.Begin(), "Process") == 0)
	{
		buf = new char*[SAFE_BUFFER_SIZE_PROCESS];
		intType = HANDLE_ACCESS_TYPE_PROCESS;
	}
	else if (strcmp(type.Begin(), "Key") == 0)
	{
		buf = new char*[SAFE_BUFFER_SIZE_REGKEY];
		intType = HANDLE_ACCESS_TYPE_REGKEY;
	}
	
	// Retrieve mask dissection information.
	DWORD sz = 0;
	GetHandleObjectAccess(intType, mask, buf, &sz);
	
	for (DWORD i = 0; i < sz; ++i)
	{
		this->mAccessConstants.Add(buf[i]);
	}
	
	// Sanity checking on the buffer. If its NULL, nothing has to be released.
	if (buf)
	{
		delete[] buf;
	}
}

CrySystemHandleAccessMaskWindow::~CrySystemHandleAccessMaskWindow()
{
	
}

void CrySystemHandleAccessMaskWindow::FormClose()
{
	this->Close();
}