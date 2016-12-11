#include "CrySystemHandleInformationWindow.h"
#include "CrySystemHandleAccessMaskWindow.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"
#include "ImlProvider.h"

// The handles are saved globally to simplify the code necessary.
Vector<Win32HandleInformation> mHandleCollection;

// Gets the string representation of a handle.
String GetHandleValue(const int index)
{
	return Format("%lX", mHandleCollection[index].Handle);
}

// Gets the object type name of a handle.
String GetHandleObject(const int index)
{
	return mHandleCollection[index].ObjectType;
}

// Gets the number of references to a handle.
String GetHandleReferences(const int index)
{
	return Format("%i", mHandleCollection[index].ReferenceCount);
}

// Gets the name of a handle.
String GetHandleName(const int index)
{
	return mHandleCollection[index].ObjectName;
}

// Gets the string representation of the access mask number of a handle.
String GetHandleAccess(const int index)
{
	return Format("%lX", mHandleCollection[index].Access);
}

// The CrySystemHandleInformationWindow default constructor.
CrySystemHandleInformationWindow::CrySystemHandleInformationWindow(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Open Handles").Zoomable().Sizeable().SetRect(0, 0, 600 , 200);
	
	this->mOK <<= THISBACK(CloseButtonClicked);
	
	this->mOpenHandles.CryAddRowNumColumn("Handle", 10).SetConvert(Single<IndexBasedValueConvert<GetHandleValue>>());
	this->mOpenHandles.CryAddRowNumColumn("Object", 30).SetConvert(Single<IndexBasedValueConvert<GetHandleObject>>());
	this->mOpenHandles.CryAddRowNumColumn("References", 15).SetConvert(Single<IndexBasedValueConvert<GetHandleReferences>>());
	this->mOpenHandles.CryAddRowNumColumn("Name", 40).SetConvert(Single<IndexBasedValueConvert<GetHandleName>>());
	this->mOpenHandles.CryAddRowNumColumn("Access", 10).SetConvert(Single<IndexBasedValueConvert<GetHandleAccess>>());
	
	this->mOpenHandles.WhenBar = THISBACK(HandlesListWhenBar);
	
	*this
		<< this->mOpenHandles.HSizePos(5, 5).VSizePos(5, 35)
		<< this->mTotalHandles.LeftPos(5, 130).BottomPos(5, 25)
		<< this->mOK.Ok().SetLabel("OK").RightPos(5, 50).BottomPos(5, 25)
	;
	
	this->Initialize();
}

// The CrySystemHandleInformationWindow default destructor.
CrySystemHandleInformationWindow::~CrySystemHandleInformationWindow()
{
	
}

// Executed when the user right clicks a handle.
void CrySystemHandleInformationWindow::HandlesListWhenBar(Bar& pBar)
{
	pBar.Add("Close Handle", THISBACK(CloseRemoteHandleClicked));
	
	// If the handle object type is a suitable mask dissection object, add button.
	const int row = this->mOpenHandles.GetCursor();
	if (row >= 0 && mHandleCollection.GetCount())
	{
		const Win32HandleInformation& handle = mHandleCollection[row];
		if (strcmp(handle.ObjectType.Begin(), "File") == 0 || strcmp(handle.ObjectType.Begin(), "Thread") == 0 || strcmp(handle.ObjectType.Begin(), "Process") == 0
			|| strcmp(handle.ObjectType.Begin(), "Key") == 0 || strcmp(handle.ObjectType.Begin(), "Directory") == 0)
		{
			pBar.Separator();
			pBar.Add("View Access", THISBACK(ViewAccessButtonClicked));
		}
	}
}

// Closes the selected handle.
void CrySystemHandleInformationWindow::CloseRemoteHandleClicked()
{
	if (!CloseRemoteHandle(mMemoryScanner->GetHandle(), (HANDLE)mHandleCollection[this->mOpenHandles.GetCursor()].Handle))
	{
		Prompt("Fatal Error", CtrlImg::error(), "Failed to close the remote handle!", "OK");
	}
	
	// Refresh the list of handles.
	this->Initialize();
}

// Opens a new dialog that shows the string representation of all access masks applied to the selected handle.
void CrySystemHandleInformationWindow::ViewAccessButtonClicked()
{
	const int row = this->mOpenHandles.GetCursor();
	CrySystemHandleAccessMaskWindow* cshamw = new CrySystemHandleAccessMaskWindow(mHandleCollection[row].ObjectType, mHandleCollection[row].Access, CrySearchIml::ViewHandlesButton());
	cshamw->Execute();
	delete cshamw;
}

// Executed when the user closes the handles window.
void CrySystemHandleInformationWindow::CloseButtonClicked()
{
	mHandleCollection.Clear();
	this->Close();
}

// Initializes the window: retrieves and formats handle information.
void CrySystemHandleInformationWindow::Initialize()
{
	// Clear the list.
	mHandleCollection.Clear();
	
	// Retrieve the list of handles that are associated to the opened process.
	EnumerateHandles(mMemoryScanner->GetProcessId(), mHandleCollection);
	this->mOpenHandles.SetVirtualCount(mHandleCollection.GetCount());
	
	// Set the total handle count in a label in the window.
	this->mTotalHandles.SetLabel(Format("Total %i handles", mHandleCollection.GetCount()));
}