#include "CryPointerScanWindow.h"
#include "ImlProvider.h"
#include "CryPointerScanSettings.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"

#define POINTER_SCAN_TIMECALLBACK	25

// Storage for the pointer scan results.
Vector<PointerScanResult> PointerScanResults;

// Retrieves the string representation of the base address in a pointer scan result.
String GetPointerScanBaseAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(PointerScanResults[index].BaseAddress);
#else
	return FormatHexadecimalIntSpecial(PointerScanResults[index].BaseAddress);
#endif
}

// Retrieves the string representation of the offsets in a pointer scan result.
String GetPointerScanOffsets(const int index)
{
	const PointerScanResult& ptrRes = PointerScanResults[index];
	const int count = ptrRes.PointerOffsets.GetCount();
	String buf;
	buf.Reserve(count * sizeof(int));
	
	// Walk the offsets list and create a string representation.
	for (int i = 0; i < count; ++i)
	{
		buf += FormatInt64HexUpper(ptrRes.PointerOffsets[i]);
		
		// Add a comma if this is not the last offset.
		if (i != count - 1)
		{
			buf += ", ";
		}
	}
	
	// End string and return.
	return buf;
}

// Retrieves the string representation of the value in a pointer scan result.
String GetPointerScanValue(const int index)
{
	const PointerScanResult& ptrRes = PointerScanResults[index];
	
	// Walk the offsets list, and traverse pointer.
	const int count = ptrRes.PointerOffsets.GetCount();
	SIZE_T cur_ptr = ptrRes.BaseAddress;
	bool success = true;
	const int read_size = mMemoryScanner->IsX86Process() ? sizeof(int) : sizeof(__int64);
	for (int i = 0; i < count; ++i)
	{
		if (!mMemoryScanner->Peek(cur_ptr + ptrRes.PointerOffsets[i], read_size, &cur_ptr))
		{
			success = false;
		}
	}
	
	// Return string representation or ??? if unable to find value.
	return success ? FormatInt64HexUpper(cur_ptr) : "???";
}

// ---------------------------------------------------------------------------------------------

// CryPointerScanWindow default constructor.
CryPointerScanWindow::CryPointerScanWindow(const Image& icon)
{
	this->Title("Pointer Scan").Zoomable().Sizeable().Icon(icon).SetRect(0, 0, 500, 400);
	
	this->AddFrame(this->mMenuBar);
	this->mMenuBar.Set(THISBACK(WindowMenuBar));
	
	*this << this->mPointerScanResults.NoMovingHeader().SizePos();
	
	this->mPointerScanResults.WhenBar = THISBACK(PointerScanRightClick);
	this->mPointerScanResults.CryAddRowNumColumn("Base Address", 40).SetConvert(Single<IndexBasedValueConvert<GetPointerScanBaseAddress>>());
	this->mPointerScanResults.CryAddRowNumColumn("Offsets", 30).SetConvert(Single<IndexBasedValueConvert<GetPointerScanOffsets>>());
	this->mPointerScanResults.CryAddRowNumColumn("Value", 30).SetConvert(Single<IndexBasedValueConvert<GetPointerScanValue>>());
	
	// Hook up the close event, such that closing the window will finalize the pointer scanner.
	this->WhenClose = THISBACK(CloseWindow);
	
	// Load existing results if any.
	this->mPointerScanResults.SetVirtualCount(PointerScanResults.GetCount());
	this->mMenuBarStatusLabel.SetLabel(Format("%i results", PointerScanResults.GetCount()));
}

// CryPointerScanWindow default destructor.
CryPointerScanWindow::~CryPointerScanWindow()
{
	
}

// Populates the main menu.
void CryPointerScanWindow::WindowMenuBar(Bar& pBar)
{
	pBar.Add("File", THISBACK(FileMenuBar));
	pBar.Add("Edit", THISBACK(EditMenuBar));
	
	// Add a status label for the number of pointer scan results there are displayed.
	pBar.GapRight();
	pBar.Add(mMenuBarStatusLabel.SetAlign(ALIGN_RIGHT), 150);
}

// Populates the file menu.
void CryPointerScanWindow::FileMenuBar(Bar& pBar)
{
	pBar.Add("Pointer Scan", CrySearchIml::PointerScanSmall(), THISBACK(NewPointerScanClicked));
	pBar.Add("Close", CrySearchIml::ExitApplication(), THISBACK(CloseWindow));
}

// Populates the edit menu.
void CryPointerScanWindow::EditMenuBar(Bar& pBar)
{
	pBar.Add(!!PointerScanResults.GetCount(), "Clear Results", THISBACK(ClearResultsClicked));
}

// Clears the results of the pointer scan currently stored.
void CryPointerScanWindow::ClearResultsClicked()
{
	if (Prompt("Are you sure?", CtrlImg::exclamation(), "Do you want to clear the search results?", "Yes", "No"))
	{
		// Clear the search results.
		PointerScanResults.Clear();

		// Update the user interface.
		this->mPointerScanResults.SetVirtualCount(PointerScanResults.GetCount());
		this->mMenuBarStatusLabel.SetLabel(Format("%i results", PointerScanResults.GetCount()));
	}
}

// Closes the pointer scan window.
void CryPointerScanWindow::CloseWindow()
{
	// Kill the pointer scan if running.
	this->mPScanner.Kill();
	
	// Clear results or leave them be?
	
	// Close the window.
	this->Close();
}

// Populates the arrayctrl context menu.
void CryPointerScanWindow::PointerScanRightClick(Bar& pBar)
{
	
}

// Opens the new pointer scan window.
void CryPointerScanWindow::NewPointerScanClicked()
{
	SIZE_T addr = 0;
	SIZE_T maxoff = 0;
	SIZE_T maxrec = 0;
	CryPointerScanSettings* cpss = new CryPointerScanSettings(CrySearchIml::PointerScanSmall(), &addr, &maxoff, &maxrec);
	
	// Check if dialog result was OK.
	if (cpss->Execute() == 10)
	{
		// Start a new pointer scan using the parameters provided.
		this->StartNewPointerScan(addr, maxoff, maxrec);
	}
	
	delete cpss;
}

// ---------------------------------------------------------------------------------------------

// Periodically checks for new results.
void CryPointerScanWindow::PointerScanCheckForResults()
{
	// Update the user interface.
	this->mPointerScanResults.SetVirtualCount(PointerScanResults.GetCount());
	this->mMenuBarStatusLabel.SetLabel(Format("%i results", PointerScanResults.GetCount()));

	// Check for completion to reinstall the time callback.
	const bool completed = this->mPScanner.PollPointerScanCompleted();
	if (!completed)
	{
		// Reinstall the time callback.
		SetTimeCallback(100, THISBACK(PointerScanCheckForResults), POINTER_SCAN_TIMECALLBACK);
	}
}

// Executes a new pointer scan using the provided parameters.
void CryPointerScanWindow::StartNewPointerScan(const SIZE_T pAddr, const SIZE_T pMaxOff, const SIZE_T pMaxRec)
{
	// Check if the input address is valid.
	if (pAddr)
	{
		// Create a new pointer scanner and start scanning.
		this->mPScanner.StartPointerScan(pAddr, pMaxOff, pMaxRec);
		
		// Start polling for results.
		SetTimeCallback(100, THISBACK(PointerScanCheckForResults), POINTER_SCAN_TIMECALLBACK);
	}
}