#include "CryAllocateViewPagesWindow.h"
#include "MemoryScanner.h"
#include "UIUtilities.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"

// The memory allocated memory pages are saved globally while the window is open.
Vector<MemoryRegion> mAllocatedMemoryCollection;

// Gets the string representation of the memory region base address.
String GetCommittedBaseAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((__int64)mAllocatedMemoryCollection[index].BaseAddress);
#else
	return FormatHexadecimalIntSpecial((int)mAllocatedMemoryCollection[index].BaseAddress);
#endif
}

// Gets the string representation of the memory region size.
String GetCommittedRegionSize(const int index)
{
	return FormatHexadecimalIntSpecial((int)mAllocatedMemoryCollection[index].MemorySize);
}

// ---------------------------------------------------------------------------------------------

// CryAllocateViewPagesWindow default constructor.
CryAllocateViewPagesWindow::CryAllocateViewPagesWindow() : CryDialogTemplate(CrySearchIml::AllocateMemoryButton())
{
	this->Title("View Committed Pages").SetRect(0, 0, 300, 200);
	this->Rejector(mClose, IDCANCEL);
	
	this->mClose <<= THISBACK(CloseButton);
	
	this->mPagesCtrl.CryAddRowNumColumn("Base").SetConvert(Single<IndexBasedValueConvert<GetCommittedBaseAddress>>());
	this->mPagesCtrl.CryAddRowNumColumn("Size").SetConvert(Single<IndexBasedValueConvert<GetCommittedRegionSize>>());
	this->mPagesCtrl.WhenBar = THISBACK(PagesListRightClick);
	
	*this
		<< this->mNumberOfCommittedPages.HSizePos(5, 5).TopPos(5, 25)
		<< this->mPagesCtrl.HSizePos(5, 5).VSizePos(35, 35)
		<< this->mClose.SetLabel("Close").BottomPos(5, 25).RightPos(5, 60)
	;
	
	// Retrieve window contents.
	this->Initialize();
}

// CryAllocateViewPagesWindow default destructor.
CryAllocateViewPagesWindow::~CryAllocateViewPagesWindow()
{
	
}

// Executed when the user right-clicks the pages list.
void CryAllocateViewPagesWindow::PagesListRightClick(Bar& pBar)
{
	if (this->mPagesCtrl.GetCursor() >= 0 && mAllocatedMemoryCollection.GetCount() > 0)
	{
		pBar.Add("Free Page", THISBACK(FreePageButton));
	}
}

// Attempts to free the selected page.
void CryAllocateViewPagesWindow::FreePageButton()
{
	const MemoryRegion& selRegion = mAllocatedMemoryCollection[this->mPagesCtrl.GetCursor()];
	
	// Try to free the selected page.
	if (!VirtualFreeEx(mMemoryScanner->GetHandle(), (void*)selRegion.BaseAddress, 0, MEM_RELEASE))
	{
		Prompt("Fatal Error", CtrlImg::error(), "The selected memory page could not be freed.", "OK");
	}
	
	// Refresh the user interface, regardless of whether the operation succeeded or not.
	this->Initialize();
}

// Initializes the window: queries pages and views them.
void CryAllocateViewPagesWindow::Initialize()
{
	SIZE_T incAddress = 0;
	MEMORY_BASIC_INFORMATION block;
	
	// Clear the existing pages, if any.
	this->mPagesCtrl.Clear();
	mAllocatedMemoryCollection.Clear();
	
	// Query virtual pages inside target process.
	while (VirtualQueryEx(mMemoryScanner->GetHandle(), (void*)incAddress, &block, sizeof(block)))
	{
		// We only want committed pages.
		if (block.State == MEM_COMMIT)
	    {
	        MemoryRegion memReg;
		    memReg.BaseAddress = (SIZE_T)block.BaseAddress;
			memReg.MemorySize = block.RegionSize;
			mAllocatedMemoryCollection << memReg;
	    }
	
		const SIZE_T oldIncAddress = incAddress;
	    incAddress = (SIZE_T)block.BaseAddress + block.RegionSize;
	    
	    // Compatibility issue between wow64 and x64 processes on some systems causes infinite loop.
		if (oldIncAddress > (SIZE_T)block.BaseAddress)
		{
			break;
		}
	}
	
	// Update user interface components.
	this->mPagesCtrl.SetVirtualCount(mAllocatedMemoryCollection.GetCount());
	this->mNumberOfCommittedPages.SetLabel(Format("Total %i committed pages", mAllocatedMemoryCollection.GetCount()));
}

// Closes the dialog.
void CryAllocateViewPagesWindow::CloseButton()
{
	// Clear the list of allocated pages and close the dialog.
	mAllocatedMemoryCollection.Clear();
	this->Close();
}