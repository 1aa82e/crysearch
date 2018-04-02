#include "CodeCaveScannerWindow.h"
#include "Disassembler.h"
#include "UIUtilities.h"

// Default size for a code cave.
#define DEFAULT_CODE_CAVE_SIZE 16

// CodeCaveScannerWindow default constructor.
CodeCaveScannerWindow::CodeCaveScannerWindow(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Scan for Code Caves").Sizeable().SetRect(0, 0, 500, 220);
	
	this->mScan <<= THISBACK(ScanButtonClicked);
	this->mClose <<= THISBACK(CloseButtonClicked);
	
	this->mScanResults.WhenBar = THISBACK(RightClicked);
	
	*this
		<< this->mScanPageLabel.SetLabel("Memory Page:").LeftPos(5, 125).TopPos(5, 25)
		<< this->mScanPage.LeftPos(5, 125).TopPos(30, 25)
		<< this->mCaveSizeLabel.SetLabel("Cave Size:").LeftPos(5, 125).TopPos(60, 25)
		<< this->mCaveSize.Min(4).Max(256).LeftPos(5, 125).TopPos(90, 25)
		<< this->mScanResults.HSizePos(135, 5).VSizePos(5, 5)
		<< this->mScan.SetLabel("Scan").LeftPos(5, 60).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").LeftPos(70, 60).BottomPos(5, 25)
	;
	
	// Add columns to the array control.
	this->mScanResults.CryAddColumn("Address", 60);
	this->mScanResults.CryAddColumn("Size", 40);
	
	// Find out what the lowest and highest addresses of the opened process are.
	GetExecutableMemoryPagesList(this->memoryRegions);
	for (auto const& memReg : this->memoryRegions)
	{
		this->mScanPage.Add(FormatInt64HexUpper(memReg.BaseAddress));
	}
	
	// If we have any pages at all, set the first and last memory page as bounds.
	if (this->memoryRegions.GetCount() > 0)
	{
		this->mScanPage.SetIndex(0);
	}
	
	// Set default size of code cave.
	this->mCaveSize.SetData(FormatInt(DEFAULT_CODE_CAVE_SIZE));
	
	// Create a scanner object and hook up the event handlers.
	this->ccs.ScannerStarted = THISBACK(ScannerStarted);
	this->ccs.ScannerFinished = THISBACK(ScannerFinished);
	this->ccs.ScannerResultFound = THISBACK(ScannerResultFound);
}

// CodeCaveScannerWindow default destructor.
CodeCaveScannerWindow::~CodeCaveScannerWindow()
{
	
}

// Executed when the user right clicks the code cave result list.
void CodeCaveScannerWindow::RightClicked(Bar& pBar)
{
	// Only add the copy button if an item is selected.
	const int cursor = this->mScanResults.GetCursor();
	if (cursor > 0 && this->mScanResults.GetCount())
	{
		pBar.Add("Copy Address", CtrlImg::copy(), THISBACK(CopyCursorAddressToClipboard));
	}
}

// Copies the selected address to the clipboard.
void CodeCaveScannerWindow::CopyCursorAddressToClipboard()
{
	const int cursor = this->mScanResults.GetCursor();
	if (cursor > 0 && this->mScanResults.GetCount())
	{
		// Copy the address to the clipboard.
		WriteClipboardText(this->mScanResults.Get(cursor, 0));
	}
}

// Executed when the code cave scanner has started.
void CodeCaveScannerWindow::ScannerStarted()
{
	this->mScan.Disable();
	this->mCaveSize.Disable();
	this->mScanPage.Disable();
}

// Executed when the code cave scanner has finished.
void CodeCaveScannerWindow::ScannerFinished()
{
	PostCallback(THISBACK(ScannerFinishedThreadSafe));
}

// Executed when the code cave scanner has finished, but in the main window thread.
void CodeCaveScannerWindow::ScannerFinishedThreadSafe()
{
	this->mScan.Enable();
	this->mCaveSize.Enable();
	this->mScanPage.Enable();
}

// Executed when the code cave scanner has found a result.
void CodeCaveScannerWindow::ScannerResultFound(const SIZE_T addr, const int sz)
{
	PostCallback(THISBACK2(ScannerResultFoundThreadSafe, addr, sz));
}

// Executed when the code cave scanner has found a result, but in the main window thread.
void CodeCaveScannerWindow::ScannerResultFoundThreadSafe(const SIZE_T addr, const int sz)
{
	this->mScanResults.Add(FormatInt64HexUpper(addr), sz);
}

// Executed when the user clicks the scan button.
void CodeCaveScannerWindow::ScanButtonClicked()
{
	// Check if the cave size is reasonable.
	const int caveSize = this->mCaveSize.GetData();
	if (caveSize >= 4 && caveSize <= 256)
	{
		// Check if a valid page was selected.
		const int cursor = this->mScanPage.GetIndex();
		if (cursor >= 0 && this->memoryRegions.GetCount() > 0)
		{
			// Clear the previous results, if any.
			this->mScanResults.Clear();
			
			// Start the code cave scanner.
			this->ccs.ScanForCodeCaves(this->memoryRegions[cursor].BaseAddress, this->memoryRegions[cursor].MemorySize, caveSize);
		}
	}
	else
	{
		Prompt("Input Error", CtrlImg::error(), "The code cave size must be between 4 and 256!", "OK");
	}
}

// Executed when the user clicks the close button.
void CodeCaveScannerWindow::CloseButtonClicked()
{
	// Kill the code cave scanner if necessary.
	this->ccs.Kill();
	this->Close();
}