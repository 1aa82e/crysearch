#include "CryDisasmCtrl.h"
#include "CrySignatureGenerationWindow.h"
#include "CryByteArrayGenerationWindow.h"
#include "CryDisasmGoToAddressDialog.h"
#include "UIUtilities.h"
#include "FrontendGlobalDef.h"
#include "BackendGlobalDef.h"
#include "ImlProvider.h"

// Extern declarations are needed here to prevent errors.
extern Vector<LONG_PTR> DisasmVisibleLines;
MemoryRegion CurrentExecutableMemoryPage;

#define DISASSEMBLER_PROGRESS_TIMECALLBACK		40
#define SELECTCOUNT_THRESHOLD					256

// Retrieves the disassembly line index by address.
const int GetDisasmLineIndexFromAddress(const SIZE_T address)
{
	const SIZE_T* next = NULL;
	const int count = DisasmVisibleLines.GetCount();
	
	// Loop the addresses inside the currently disassembled area.
	for (int i = 0; i < count; ++i)
	{
		const int nextIndex = i + 1;
		if (nextIndex < count)
		{
			next = (SIZE_T*)&DisasmVisibleLines[nextIndex];
		}
		else
		{
			next = NULL;
		}
		
		if (((SIZE_T)DisasmVisibleLines[i]) >= address && (next && (*next && address < *next)))
		{
			return i;
		}
	}
	
	return 0;
}

// Creates a string representation for the instruction addresses currently visible.
String GetDisasmAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(DisasmVisibleLines[index]);
#else
	return FormatHexadecimalIntSpecial(DisasmVisibleLines[index]);
#endif
}

// Creates a string representation for the instruction bytes currently visible.
String GetDisasmBytes(const int index)
{
	ArrayOfBytes disLineBytes;
#ifdef _WIN64
	DisasmForBytes(DisasmVisibleLines[index], mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64, &disLineBytes, NULL);
#else
	DisasmForBytes(DisasmVisibleLines[index], CS_MODE_32, &disLineBytes, NULL);
#endif
	
	return BytesToString(disLineBytes.Data, disLineBytes.Size);
}

// Creates a string representation for the instructions currently visible.
String GetDisasmInstructionLine(const int index)
{
#ifdef _WIN64
	return DisasmGetLineEx(DisasmVisibleLines[index], mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64);
#else
	return DisasmGetLineEx(DisasmVisibleLines[index], CS_MODE_32);
#endif
}

// ---------------------------------------------------------------------------------------------

// Default CryDisasmCtrl constructor.
CryDisasmCtrl::CryDisasmCtrl()
{
	this->mHasPreceding = true;
	this->mHasSucceeding = true;
	
	this->AddFrame(mToolStrip);
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	*this
		<< this->disasmDisplay.MultiSelect().NoGrid().NoMovingHeader().SizePos()
	;
	
	this->disasmDisplay.CryAddRowNumColumn("Address", 20).SetConvert(Single<IndexBasedValueConvert<GetDisasmAddress>>());
	this->disasmDisplay.CryAddRowNumColumn("Bytes", 30).SetConvert(Single<IndexBasedValueConvert<GetDisasmBytes>>());
	this->disasmDisplay.CryAddRowNumColumn("Disassembly", 50).SetConvert(Single<IndexBasedValueConvert<GetDisasmInstructionLine>>());
	
	this->disasmDisplay.WhenBar = THISBACK(DisassemblyRightClick);
	
	// Initialize async helper to serve UI responsiveness for the newly opened process.
	this->mAsyncHelper.DisasmStarted = THISBACK(AsyncDisasmStarted);
}

// Default CryDisasmCtrl destructor.
CryDisasmCtrl::~CryDisasmCtrl()
{
	
}

// Populates the toolstrip inside the disassembler window.
void CryDisasmCtrl::ToolStrip(Bar& pBar)
{
	pBar.Add(this->mExecutablePagesDescriptor.SetLabel(Format("Memory Page: %llX - %llX", (LONG_PTR)CurrentExecutableMemoryPage.BaseAddress
		, (LONG_PTR)(CurrentExecutableMemoryPage.BaseAddress + CurrentExecutableMemoryPage.MemorySize))), 250);
	pBar.Add(!this->mAsyncHelper.IsRunning() && this->mHasPreceding, "Previous Page", CrySearchIml::ArrowUpSmall(), THISBACK(MoveToPreviousPage));
	pBar.Add(!this->mAsyncHelper.IsRunning() && this->mHasSucceeding, "Next Page", CrySearchIml::ArrowDownSmall(), THISBACK(MoveToNextPage));
	pBar.Separator();
	pBar.Add(!this->mAsyncHelper.IsRunning(), "Go to entrypoint", CrySearchIml::EntryPointIcon(), THISBACK(GoToEntryPointClicked));
	pBar.Separator();
	pBar.Add(!this->mAsyncHelper.IsRunning(), "Signature", CrySearchIml::GenerateSignatureButton(), THISBACK(GenerateSignatureButtonClicked));
	pBar.Add(!this->mAsyncHelper.IsRunning(), "Byte-array", CrySearchIml::GenerateByteArrayButton(), THISBACK(GenerateByteArrayButtonClicked));
	pBar.ToolGapRight();
	
	// The contents of the page size label should be set according to the current state.
#ifdef _WIN64
	pBar.Add(this->mPageSizeInDisasm.SetLabel("Page Size: " + FormatInt64HexUpper(this->mAsyncHelper.GetCurrentPageSize())).SetAlign(ALIGN_RIGHT), 150);
#else
	pBar.Add(this->mPageSizeInDisasm.SetLabel("Page Size: " + FormatHexadecimalIntSpecial(this->mAsyncHelper.GetCurrentPageSize())).SetAlign(ALIGN_RIGHT), 150);
#endif
}

// Executed when the user right-clicks the disassembly region in the user interface.
void CryDisasmCtrl::DisassemblyRightClick(Bar& pBar)
{
	// Whether an item is selected or not, these items should be always added to the menu.
	pBar.Add(!this->mAsyncHelper.IsRunning(), "Go to Address\tCTRL + G", THISBACK(GoToAddressButtonClicked));
	pBar.Separator();
	
	// One item must be always selected.
	const int cursor = this->disasmDisplay.GetCursor();
	if ((cursor >= 0 && DisasmVisibleLines.GetCount() > 0))
	{
		pBar.Add("Copy\t\tCTRL + C", CtrlImg::copy(), THISBACK(CopyCursorLineToClipboard));
		
		// Debugger menu items should depend on whether the debugger is attached or not.
		const bool canDbg = (mDebugger && mDebugger->IsDebuggerAttached()) && this->disasmDisplay.GetSelectCount() < 2;
		if (mDebugger->FindBreakpoint(DisasmVisibleLines[cursor]) == -1)
		{
			pBar.Add(canDbg, "Set Breakpoint", CrySearchIml::SetBreakpoint(), THISBACK(SetBreakpointMenu));
		}
		else
		{
			pBar.Add(canDbg, "Remove Breakpoint", CrySearchIml::DeleteButton(), THISBACK(RemoveBreakpointButtonClicked));
		}
		
		// Below the single selection menu items, this item should go for both, even though it should be located below.
		pBar.Separator();
		pBar.Add(!mMemoryScanner->IsReadOnlyOperationMode() && !this->mAsyncHelper.IsRunning(), "NOP Selected", THISBACK(NopSelectedCode));
		pBar.Add(!this->mAsyncHelper.IsRunning(), "Generate", THISBACK(DisasmGenerateSubmenu));
		pBar.Separator();
		pBar.Add(!this->mAsyncHelper.IsRunning(), "Go to entrypoint", CrySearchIml::EntryPointIcon(), THISBACK(GoToEntryPointClicked));
	}
}

// Populates the generation submenu for the disassembly right-click menu.
void CryDisasmCtrl::DisasmGenerateSubmenu(Bar& pBar)
{
	pBar.Add("Signature", CrySearchIml::GenerateSignatureButton(), THISBACK(GenerateSignatureButtonClicked));
	pBar.Add("Byte-array", CrySearchIml::GenerateByteArrayButton(), THISBACK(GenerateByteArrayButtonClicked));
}

// Handles keyboard shortcut combinations (Copy / Go-to-address).
bool CryDisasmCtrl::Key(dword key, int count)
{
	if (key == K_CTRL_G)
	{
		this->GoToAddressButtonClicked();
		return true;
	}
	else if (key == K_CTRL_C)
	{
		this->CopyCursorLineToClipboard();
		return true;
	}
	
	return false;
}

// Replaces a sequence of instructions with NOP (0x90) instructions.
void CryDisasmCtrl::NopSelectedCode()
{
	SIZE_T first_address = 0;
	bool first_selected = false;
	
	// Loop through the rows to see which are selected.
	const int count = this->disasmDisplay.GetCount();
	for (int i = 0; i < count; ++i)
	{
		if (this->disasmDisplay.IsSelected(i))
		{
			// Save the address of the row that was first selected as address to move the cursor to after NOPing.
			const SIZE_T address = DisasmVisibleLines[i];
			if (!first_selected)
			{
				first_address = address;
				first_selected = true;
			}
			
			// Disassemble the instruction bytes at the selected address to see how many bytes need to be NOPed.
			ArrayOfBytes disLineBytes;
#ifdef _WIN64
			DisasmGetLine(address, mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64, &disLineBytes);
#else
			DisasmGetLine(address, CS_MODE_32, &disLineBytes);
#endif
			
			// Write NOP instructions to the selected memory location.
			memset(disLineBytes.Data, 0x90, disLineBytes.Size);
			mMemoryScanner->PokeB(address, disLineBytes);
		}
	}
	
	// Redo the disassembly for the page the selected address is in and move to this address again.
	this->MoveToAddress(first_address);
}

// Moves the selection to the entrypoint of the opened process.
void CryDisasmCtrl::GoToEntryPointClicked()
{
	// Get the entrypoint address.
#ifdef _WIN64
	SIZE_T epAddress = LoadedProcessPEInformation.PEFields.GetCount() > 0 ? (*mModuleManager)[0].BaseAddress + ScanInt64(LoadedProcessPEInformation.PEFields.Get("Address of entrypoint").ToString(), NULL, 16) : 0;
#else
	SIZE_T epAddress = LoadedProcessPEInformation.PEFields.GetCount() > 0 ? (*mModuleManager)[0].BaseAddress + ScanInt(LoadedProcessPEInformation.PEFields.Get("Address of entrypoint").ToString(), NULL, 16) : 0;
#endif

	// Move to the entrypoint address.
	if (epAddress)
	{
		this->MoveToAddress(epAddress);
	}
	else
	{
		Prompt("Fatal Error", CtrlImg::error(), "Could not retrieve the entrypoint!", "OK");
	}
}

// Executes a new window that generates a signature from the selected instructions.
void CryDisasmCtrl::GenerateSignatureButtonClicked()
{
	// If the select count of a signature is more than a threshold value, we should block generation.
	if (this->disasmDisplay.GetSelectCount() > SELECTCOUNT_THRESHOLD)
	{
		Prompt("Input Error", CtrlImg::error(), "You can select no more than 256 rows!", "OK");
		return;
	}
	
	// Aggregate all selected rows in an input vector for the generation.
	Vector<int> selectedRows;
	const int count = this->disasmDisplay.GetCount();
	for (int i = 0; i < count; ++i)
	{
		// Check which rows are selected for the signature generation.
		if (this->disasmDisplay.IsSelected(i))
		{
			selectedRows.Add(i);
		}
	}
	
	// Launch signature generation form with selected rows as parameter.
	CrySignatureGenerationWindow* csgw = new CrySignatureGenerationWindow(selectedRows);
	csgw->Execute();
	delete csgw;
}

// Executes a new window that generates a byte array from the selected instructions.
void CryDisasmCtrl::GenerateByteArrayButtonClicked()
{
	// If the select count of a signature is more than a threshold value, we should block generation.
	if (this->disasmDisplay.GetSelectCount() > SELECTCOUNT_THRESHOLD)
	{
		Prompt("Input Error", CtrlImg::error(), "You can select no more than 256 rows!", "OK");
		return;
	}
	
	// Aggregate all selected rows in an input vector for the generation.
	Vector<int> selectedRows;
	const int count = this->disasmDisplay.GetCount();
	for (int i = 0; i < count; ++i)
	{
		// Check which rows are selected for the signature generation.
		if (this->disasmDisplay.IsSelected(i))
		{
			selectedRows.Add(i);
		}
	}
	
	// Launch signature generation form with selected rows as parameter.
	CryByteArrayGenerationWindow* cbagw = new CryByteArrayGenerationWindow(selectedRows);
	cbagw->Execute();
	delete cbagw;
}

// Moves to the previous executable memory page.
void CryDisasmCtrl::MoveToPreviousPage()
{
	// Get the previous memory page.
	AuxMemRegStruct aux;
	GetMemoryPageByAddress(CurrentExecutableMemoryPage.BaseAddress, CurrentExecutableMemoryPage, &aux);
	
	// Check if the previous page has a predecessor.
	AuxMemRegStruct auxPrev;
	GetMemoryPageByAddress(aux.Previous.BaseAddress, CurrentExecutableMemoryPage, &auxPrev);
	
	// If there is no preceding page, the down button must be disabled.
	if (!auxPrev.Previous.BaseAddress)
	{
		this->mHasPreceding = false;
	}

	// If we go up, the succeeding page becomes available again.
	this->mHasSucceeding = true;
	
	// Clean up the current set of disasm lines.
	this->disasmDisplay.Clear();
	DisasmVisibleLines.Clear();
	
	// Still here, so start refreshing the disasm.
	this->mAsyncHelper.Start(aux.Previous.BaseAddress, CurrentExecutableMemoryPage);
	
	// Start polling the disassembler completion state.
	SetTimeCallback(10, THISBACK(PeekDisasmCompletion), DISASSEMBLER_PROGRESS_TIMECALLBACK);
}

// Moves to the next executable memory page.
void CryDisasmCtrl::MoveToNextPage()
{
	// Get the next executable memory page.
	AuxMemRegStruct aux;
	GetMemoryPageByAddress(CurrentExecutableMemoryPage.BaseAddress, CurrentExecutableMemoryPage, &aux);

	// Check if the next page has a successor.
	AuxMemRegStruct auxNext;
	GetMemoryPageByAddress(aux.Next.BaseAddress, CurrentExecutableMemoryPage, &auxNext);

	// If there is no succeeding page, the up button must be disabled.
	if (!auxNext.Next.BaseAddress)
	{
		this->mHasSucceeding = false;
	}
	
	// If we go down, the preceding page becomes available again.
	this->mHasPreceding = true;

	// Clean up the current set of disasm lines.
	this->disasmDisplay.Clear();
	DisasmVisibleLines.Clear();
	
	// Still here, so start refreshing the disasm.
	this->mAsyncHelper.Start(aux.Next.BaseAddress, CurrentExecutableMemoryPage);
	
	// Start polling the disassembler completion state.
	SetTimeCallback(10, THISBACK(PeekDisasmCompletion), DISASSEMBLER_PROGRESS_TIMECALLBACK);
}

// Removes a breakpoint from the selected address.
void CryDisasmCtrl::RemoveBreakpointButtonClicked()
{
	mCrySearchWindowManager->GetDebuggerWindow()->Cleanup();
	mDebugger->RemoveBreakpoint(DisasmVisibleLines[this->disasmDisplay.GetCursor()]);
}

// Populates the breakpoint submenu of the right click menu.
void CryDisasmCtrl::SetBreakpointMenu(Bar& pBar)
{
	pBar.Add("Software Breakpoint", THISBACK(SetSoftwareBreakpoint));
	pBar.Add("Hardware Breakpoint", THISBACK(SetHardwareBreakpoint));
}

// Sets a software breakpoint on the selected address.
void CryDisasmCtrl::SetSoftwareBreakpoint()
{
	// If a breakpoint is already set, the function will return true after it detected an existing software breakpoint.
	const int cursor = this->disasmDisplay.GetCursor();
	if (cursor >= 0 && DisasmVisibleLines.GetCount() > 0)
	{
		mDebugger->SetBreakpoint(DisasmVisibleLines[cursor]);
	}
}

// Sets a hardware breakpoint on the selected address.
void CryDisasmCtrl::SetHardwareBreakpoint()
{
	const int cursor = this->disasmDisplay.GetCursor();
	mDebugger->SetHardwareBreakpoint(mThreadsList, DisasmVisibleLines[cursor], HWBP_SIZE_1, HWBP_TYPE_EXECUTE);
}

// Externally available for calling, this function moves the disassembly view to a specific address.
void CryDisasmCtrl::MoveToAddress(const SIZE_T address)
{
	// Memory address was not found within the address space of the process.
	MemoryRegion page;
	AuxMemRegStruct aux;
	if (!GetMemoryPageByAddress(address, page, &aux))
	{
		Prompt("Input Error", CtrlImg::error(), "The address is not within an executable section!", "OK");
		return;
	}
	
	// If there is no preceding or succeeding page, either up or down button must be disabled.
	if (!aux.Previous.BaseAddress)
	{
		this->mHasPreceding = false;
	}
	if (!aux.Next.BaseAddress)
	{
		this->mHasSucceeding = false;
	}
	
	// Clean up the current set of disasm lines.
	this->disasmDisplay.Clear();
	DisasmVisibleLines.Clear();
	
	// Still here, so start refreshing the disasm.
	CurrentExecutableMemoryPage = page;
	this->mAsyncHelper.Start(address, CurrentExecutableMemoryPage);
	
	// Start polling the disassembler completion state.
	SetTimeCallback(10, THISBACK(PeekDisasmCompletion), DISASSEMBLER_PROGRESS_TIMECALLBACK);
}

// Go to an address in the disassembly. This action disassembles the page in which the address
// resides and scrolls to the address in case.
void CryDisasmCtrl::GoToAddressButtonClicked()
{
	LONG_PTR newAddress;
	CryDisasmGoToAddressDialog* addrDialog = new CryDisasmGoToAddressDialog(&newAddress);
	
	if (addrDialog->Execute() == 10)
	{
		// Move to the inputted address.
		this->MoveToAddress(newAddress);
	}
	
	delete addrDialog;
}

// Copy a line of disassembly containing address, bytes and opcodes to the clipboard.
void CryDisasmCtrl::CopyCursorLineToClipboard()
{
	const int cursor = this->disasmDisplay.GetCursor();
	if (cursor > 0 && this->disasmDisplay.GetCount())
	{
		WriteClipboardText(GetDisasmAddress(cursor) + "\t" + GetDisasmBytes(cursor) + "\t" + GetDisasmInstructionLine(cursor));
	}
}

// Clears the whole disassembly window, which includes the pages list and the disassembly list.
void CryDisasmCtrl::ClearList()
{
	// Make sure the disassembler has been fully killed before closing the process.
	this->mAsyncHelper.Kill();
	
	// Kill the progress callback.
	KillTimeCallback(DISASSEMBLER_PROGRESS_TIMECALLBACK);
	
	// Clear the user interface controls before clearing the data.
	this->disasmDisplay.Clear();
	
	// Clear the list of disassembly lines after the disassembler has been killed in order to prevent trouble.
	DisasmVisibleLines.Clear();
}

// Callback that executes when the asynchronous disassembly process was kicked off.
void CryDisasmCtrl::AsyncDisasmStarted()
{
	// Block controls that can create a risk for application stability.
	this->disasmDisplay.Disable();
	
	// Update the toolbar to disable buttons during disassembly.
	this->UpdateToolbar();
}

// Peeks the disassembler for its completion state.
void CryDisasmCtrl::PeekDisasmCompletion()
{
	// Check whether the disassembler has completed.
	SIZE_T address;
	if (this->mAsyncHelper.PeekIsFinished(&address))
	{
		// Re-enable controls that were blocked for stability reasons.
		this->disasmDisplay.Enable();
		
		// Update controls to fit core application process results.
		this->disasmDisplay.SetVirtualCount(DisasmVisibleLines.GetCount());
		
		// Re-enable the disabled buttons in the toolbar.
		this->UpdateToolbar();
		
		// Scroll down to the selected address.
		const int newRow = GetDisasmLineIndexFromAddress(address);
		this->disasmDisplay.ScrollInto(newRow + 5 > DisasmVisibleLines.GetCount() ? newRow : newRow + 5);
		this->disasmDisplay.Select(newRow);
	}
	else
	{
		// Restart polling the disassembler completion state.
		SetTimeCallback(10, THISBACK(PeekDisasmCompletion), DISASSEMBLER_PROGRESS_TIMECALLBACK);
	}
}

// Initializes the control state to entrypoint disassembly view.
void CryDisasmCtrl::Initialize()
{
	// Clear list to put new disassembly.
	this->disasmDisplay.Clear();
	DisasmVisibleLines.Clear();

	// Try to get the entrypoint address, we prefer to start there.
	const SIZE_T epAddress = LoadedProcessPEInformation.PEFields.GetCount() > 0 ? (SIZE_T)((*mModuleManager)[0].BaseAddress
		+ ScanInt64(LoadedProcessPEInformation.PEFields.Get("Address of entrypoint").ToString(), NULL, 16)) : 0;

	// Get the first executable memory page in case the entrypoint cannot be retrieved.
	AuxMemRegStruct aux;
	GetMemoryPageByAddress(epAddress, CurrentExecutableMemoryPage, &aux);

	// If there is no preceding or succeeding page, either up or down button must be disabled.
	if (!aux.Previous.BaseAddress)
	{
		this->mHasPreceding = false;
	}
	if (!aux.Next.BaseAddress)
	{
		this->mHasSucceeding = false;
	}
	
	// Initialize UI-seperate on another thread to speed up the process.
	this->mAsyncHelper.Start(epAddress ? epAddress : CurrentExecutableMemoryPage.BaseAddress, CurrentExecutableMemoryPage);
	
	// Start polling the disassembler completion state.
	SetTimeCallback(10, THISBACK(PeekDisasmCompletion), DISASSEMBLER_PROGRESS_TIMECALLBACK);
}

// Updates the toolbar inside this lower pane window instance.
void CryDisasmCtrl::UpdateToolbar()
{
	this->mToolStrip.Set(THISBACK(ToolStrip));
}