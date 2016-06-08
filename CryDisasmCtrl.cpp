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
extern Vector<MemoryRegion> mExecutablePagesList;

// Retrieves the disassembly line index by address.
const int GetDisasmLineIndexFromAddress(const SIZE_T address)
{
	const LONG_PTR* next = NULL;
	const int count = DisasmVisibleLines.GetCount();
	
	for (int i = 0; i < count; ++i)
	{
		const int nextIndex = i + 1;
		if (nextIndex < count)
		{
			next = &DisasmVisibleLines[nextIndex];
		}
		else
		{
			next = NULL;
		}

		const LONG_PTR signedAddr = address;
		if (DisasmVisibleLines[i] >= signedAddr && (next && (*next && signedAddr < *next)))
		{
			return i;
		}
	}
	
	return 0;
}

// Virtual column retrieval functions for the disassembler.
String GetDisasmAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper(DisasmVisibleLines[index]);
#else
	return FormatHexadecimalIntSpecial(DisasmVisibleLines[index]);
#endif
}

String GetDisasmBytes(const int index)
{
	ArrayOfBytes disLineBytes;
#ifdef _WIN64
	DisasmGetLine(DisasmVisibleLines[index], mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, &disLineBytes);
#else
	DisasmGetLine(DisasmVisibleLines[index], ARCH_X86, &disLineBytes);
#endif
	
	return BytesToString(disLineBytes.Data, disLineBytes.Size);
}

String GetDisasmInstructionLine(const int index)
{
#ifdef _WIN64
	return DisasmGetLine(DisasmVisibleLines[index], mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, NULL);
#else
	return DisasmGetLine(DisasmVisibleLines[index], ARCH_X86, NULL);
#endif
}

String GetMemoryPageForDropList(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((__int64)mExecutablePagesList[index].BaseAddress) + " - " + FormatInt64HexUpper((__int64)(mExecutablePagesList[index].BaseAddress + mExecutablePagesList[index].MemorySize));
#else
	return FormatHexadecimalIntSpecial((int)mExecutablePagesList[index].BaseAddress) + " - " + FormatHexadecimalIntSpecial((int)(mExecutablePagesList[index].BaseAddress + mExecutablePagesList[index].MemorySize));
#endif
}

// ---------------------------------------------------------------------------------------------

CryDisasmCtrl::CryDisasmCtrl()
{
	this->AddFrame(mToolStrip);
	this->mToolStrip.Set(THISBACK(ToolStrip));
	
	*this
		<< this->disasmDisplay.MultiSelect().NoGrid().NoMovingHeader().SizePos()
	;
	
	this->disasmDisplay.CryAddRowNumColumn("Address", 20).SetConvert(Single<IndexBasedValueConvert<GetDisasmAddress>>());
	this->disasmDisplay.CryAddRowNumColumn("Bytes", 30).SetConvert(Single<IndexBasedValueConvert<GetDisasmBytes>>());
	this->disasmDisplay.CryAddRowNumColumn("Disassembly", 50).SetConvert(Single<IndexBasedValueConvert<GetDisasmInstructionLine>>());
	
	this->disasmDisplay.WhenBar = THISBACK(DisassemblyRightClick);
	
	this->mExecutablePages.SetConvert(Single<IndexBasedValueConvert<GetMemoryPageForDropList>>());
	this->mExecutablePages.WhenDrop = THISBACK(ExecutablePagesDropped);
	this->mExecutablePages.WhenAction = THISBACK(ExecutablePageSelected);
	
	this->mAsyncHelper = NULL;
}

CryDisasmCtrl::~CryDisasmCtrl()
{
	
}

void CryDisasmCtrl::ToolStrip(Bar& pBar)
{
	pBar.Add(this->mExecutablePagesDescriptor.SetLabel("Page: "));
	pBar.Add(this->mExecutablePages, 200);
	pBar.Separator();
	pBar.Add("Signature", CrySearchIml::GenerateSignatureButton(), THISBACK(GenerateSignatureButtonClicked));
	pBar.Add("Byte-array", CrySearchIml::GenerateByteArrayButton(), THISBACK(GenerateByteArrayButtonClicked));
	pBar.ToolGapRight();
	pBar.Add(this->mPageSizeInDisasm.SetLabel("Page Size: 0").SetAlign(ALIGN_RIGHT), 150);
}

void CryDisasmCtrl::DisassemblyRightClick(Bar& pBar)
{
	// Whether an item is selected or not, these items should be always added to the menu.
	pBar.Add("Go to Address\tCTRL + G", THISBACK(GoToAddressButtonClicked));
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
		pBar.Add("NOP Selected", THISBACK(NopSelectedCode));
		pBar.Add("Generate", THISBACK(DisasmGenerateSubmenu));
	}
}

void CryDisasmCtrl::DisasmGenerateSubmenu(Bar& pBar)
{
	pBar.Add("Signature", CrySearchIml::GenerateSignatureButton(), THISBACK(GenerateSignatureButtonClicked));
	pBar.Add("Byte-array", CrySearchIml::GenerateByteArrayButton(), THISBACK(GenerateByteArrayButtonClicked));
}

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
			DisasmGetLine(address, mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, &disLineBytes);
#else
			DisasmGetLine(address, ARCH_X86, &disLineBytes);
#endif
			
			// Write NOP instructions to the selected memory location.
			memset(disLineBytes.Data, 0x90, disLineBytes.Size);
			mMemoryScanner->Poke(address, disLineBytes);
		}
	}
	
	// Redo the disassembly for the page the selected address is in and move to this address again.
	this->MoveToAddress(first_address);
}

void CryDisasmCtrl::GenerateSignatureButtonClicked()
{
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

void CryDisasmCtrl::GenerateByteArrayButtonClicked()
{
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

void CryDisasmCtrl::RemoveBreakpointButtonClicked()
{
	mCrySearchWindowManager->GetDebuggerWindow()->Cleanup();
	mDebugger->RemoveBreakpoint(DisasmVisibleLines[this->disasmDisplay.GetCursor()]);
}

void CryDisasmCtrl::SetBreakpointMenu(Bar& pBar)
{
	pBar.Add("Software Breakpoint", THISBACK(SetSoftwareBreakpoint));
	pBar.Add("Hardware Breakpoint", THISBACK(SetHardwareBreakpoint));
}

void CryDisasmCtrl::SetSoftwareBreakpoint()
{
	// If a breakpoint is already set, the function will return true after it detected an existing software breakpoint.
	const int cursor = this->disasmDisplay.GetCursor();
	if (cursor >= 0 && DisasmVisibleLines.GetCount() > 0)
	{
		mDebugger->SetBreakpoint(DisasmVisibleLines[cursor]);
	}
}

void CryDisasmCtrl::SetHardwareBreakpoint()
{
	const int cursor = this->disasmDisplay.GetCursor();
	mDebugger->SetHardwareBreakpoint(mThreadsList, DisasmVisibleLines[cursor], HWBP_SIZE_1, HWBP_TYPE_EXECUTE);
}

// Externally available for calling, this function moves the disassembly view to a specific address.
void CryDisasmCtrl::MoveToAddress(const SIZE_T address)
{
	// Memory address was not found within the address space of the process.
	if (!GetPageFromAddress(address))
	{
		Prompt("Input Error", CtrlImg::error(), "The address is not within an executable section of the process!", "OK");
		return;
	}
	
	// Still here, so start refreshing the disasm.
	this->disasmDisplay.Clear();
	this->mAsyncHelper->Start(address);
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

// Executed when the list is opened, but before it is actually displayed.
void CryDisasmCtrl::ExecutablePagesDropped()
{
	// Refresh pages in the toolbar droplist for manual selection.
	RefreshExecutablePages(mExecutablePagesList);
	this->mExecutablePages.SetCount(mExecutablePagesList.GetCount());
}

// Executed when a new item is selected in the virtual pages drop list.
void CryDisasmCtrl::ExecutablePageSelected()
{
	const int cursor = this->mExecutablePages.GetIndex();
	if (cursor >= 0 && mExecutablePagesList.GetCount() > 0)
	{
		const MemoryRegion& found = mExecutablePagesList[cursor];
		this->disasmDisplay.Clear();
		this->mAsyncHelper->Start(found.BaseAddress);
	}
}

// Clears the whole disassembly window, which includes the pages list and the disassembly list.
void CryDisasmCtrl::ClearList()
{
	// Make sure the disassembler has been fully killed before closing the process.
	this->mAsyncHelper->Kill();
	delete this->mAsyncHelper;
	
	// Clear the list of disassembly lines after the disassembler has been killed in order to prevent trouble.
	DisasmVisibleLines.Clear();
	mExecutablePagesList.Clear();
	
	this->mExecutablePages.SetCount(0);
	this->disasmDisplay.Clear();
}

// Callback that executes when the asynchronous disassembly process was kicked off.
void CryDisasmCtrl::AsyncDisasmStarted()
{
	// Block controls that can create a risk for application stability.
	this->mExecutablePages.Disable();
	this->disasmDisplay.Disable();
}

// Prepration completed event.
void CryDisasmCtrl::AsyncDisasmCompleted(SIZE_T address)
{
	PostCallback(THISBACK1(AsyncDisasmCompletedThreadSafe, address));
}

void CryDisasmCtrl::AsyncDisasmCompletedThreadSafe(const SIZE_T address)
{
	// Re-enable controls that were blocked for stability reasons.
	this->mExecutablePages.Enable();
	this->disasmDisplay.Enable();
	
	// Update controls to fit core application process results.
	this->disasmDisplay.SetVirtualCount(DisasmVisibleLines.GetCount());
	
	SIZE_T size = 0;
	const int index = GetPageIndexFromAddress(address, &size);
	if (index >= 0 && index < mExecutablePagesList.GetCount())
	{
		this->mExecutablePages.SetIndex(index);
	}
	
	// Scroll down to the selected address.
	const int newRow = GetDisasmLineIndexFromAddress(address);
	this->disasmDisplay.ScrollInto(newRow + 5 > DisasmVisibleLines.GetCount() ? newRow : newRow + 5);
	this->disasmDisplay.Select(newRow);
	this->mPageSizeInDisasm.SetLabel(Format("Page Size: %s", FormatInt64HexUpper(size)));
}

// Initializes the control state to entrypoint disassembly view.
void CryDisasmCtrl::Initialize()
{
	// (Re)initialize async helper to serve UI responsiveness for the newly opened process.
	this->mAsyncHelper = new AsyncDisassembler();
	this->mAsyncHelper->DisasmStarted = THISBACK(AsyncDisasmStarted);
	this->mAsyncHelper->DisasmCompleted = THISBACK(AsyncDisasmCompleted);
	
	// Clear list to put new disassembly.
	this->disasmDisplay.Clear();
	
	// Load pages into toolbar droplist for manual selection.
	RefreshExecutablePages(mExecutablePagesList);
	this->mExecutablePages.SetCount(mExecutablePagesList.GetCount());
	
	// If the PE Headers were succesfully loaded, the entrypoint of the executable can be used to start disassembling.
	const SIZE_T pageAddress = mExecutablePagesList.GetCount() > 0 ? mExecutablePagesList[0].BaseAddress : 0;
	
#ifdef _WIN64
	SIZE_T epAddress = LoadedProcessPEInformation.PEFields.GetCount() > 0 ? (*mModuleManager)[0].BaseAddress + ScanInt64(LoadedProcessPEInformation.PEFields.Get("Address of entrypoint").ToString(), NULL, 16) : pageAddress;
#else
	SIZE_T epAddress = LoadedProcessPEInformation.PEFields.GetCount() > 0 ? (*mModuleManager)[0].BaseAddress + ScanInt(LoadedProcessPEInformation.PEFields.Get("Address of entrypoint").ToString(), NULL, 16) : pageAddress;
#endif
	
	// Initialize UI-seperate on another thread to speed up the process.
	this->mAsyncHelper->Start(epAddress);
}

// Updates the toolbar inside this lower pane window instance.
void CryDisasmCtrl::UpdateToolbar()
{
	this->mToolStrip.Set(THISBACK(ToolStrip));
}