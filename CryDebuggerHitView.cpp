#include "CryDebuggerHitView.h"
#include "CrySearchWindowManager.h"
#include "FrontendGlobalDef.h"
#include "BackendGlobalDef.h"

// The breakpoint master index is needed in both classes so externally declared here.
extern int BreakpointMasterIndex;

// Describes a register in a debugger breakpoint snapshot.
struct RegisterNameOffsetMapping
{
	char Name[4];
	DWORD Offset;
};

#ifdef _WIN64
	// Lookup table for resolving 32-bit registers to names.
	RegisterNameOffsetMapping RegisterMapping32LookupTable[] =
	{
		{ "EAX", offsetof(WOW64_CONTEXT, Eax) },
		{ "EBX", offsetof(WOW64_CONTEXT, Ebx) },
		{ "ECX", offsetof(WOW64_CONTEXT, Ecx) },
		{ "EDX", offsetof(WOW64_CONTEXT, Edx) },
		{ "EDI", offsetof(WOW64_CONTEXT, Edi) },
		{ "ESI", offsetof(WOW64_CONTEXT, Esi) },
		{ "ESP", offsetof(WOW64_CONTEXT, Esp) },
		{ "EBP", offsetof(WOW64_CONTEXT, Ebp) },
		{ "EIP", offsetof(WOW64_CONTEXT, Eip) }
	};
	
	// Lookup table for resolving 64-bit registers to names.
	RegisterNameOffsetMapping RegisterMapping64LookupTable[] =
	{
		{ "RAX", offsetof(CONTEXT, Rax) },
		{ "RBX", offsetof(CONTEXT, Rbx) },
		{ "RCX", offsetof(CONTEXT, Rcx) },
		{ "RDX", offsetof(CONTEXT, Rdx) },
		{ "RDI", offsetof(CONTEXT, Rdi) },
		{ "RSI", offsetof(CONTEXT, Rsi) },
		{ "RSP", offsetof(CONTEXT, Rsp) },
		{ "RBP", offsetof(CONTEXT, Rbp) },
		{ "RIP", offsetof(CONTEXT, Rip) },
		{ "R8", offsetof(CONTEXT, R8) },
		{ "R9", offsetof(CONTEXT, R9) },
		{ "R10", offsetof(CONTEXT, R10) },
		{ "R11", offsetof(CONTEXT, R11) },
		{ "R12", offsetof(CONTEXT, R12) },
		{ "R13", offsetof(CONTEXT, R13) },
		{ "R14", offsetof(CONTEXT, R14) },
		{ "R15", offsetof(CONTEXT, R15) }
	};
#else
	// Lookup table for resolving 32-bit registers to names.
	RegisterNameOffsetMapping RegisterMapping32LookupTable[] =
	{
		{ "EAX", offsetof(CONTEXT, Eax) },
		{ "EBX", offsetof(CONTEXT, Ebx) },
		{ "ECX", offsetof(CONTEXT, Ecx) },
		{ "EDX", offsetof(CONTEXT, Edx) },
		{ "EDI", offsetof(CONTEXT, Edi) },
		{ "ESI", offsetof(CONTEXT, Esi) },
		{ "ESP", offsetof(CONTEXT, Esp) },
		{ "EBP", offsetof(CONTEXT, Ebp) },
		{ "EIP", offsetof(CONTEXT, Eip) }
	};
#endif

// ---------------------------------------------------------------------------------------------

// Gets the name of the selected register.
String GetRegisterName(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return RegisterMapping32LookupTable[index].Name;
	}
	else
	{
		return RegisterMapping64LookupTable[index].Name;
	}
#else
	return RegisterMapping32LookupTable[index].Name;
#endif
}

// Gets a string representation of the value of a specific register.
String GetRegisterValue(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return FormatHexadecimalIntSpecial(*(LONG*)((BYTE*)(&(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Wow64Context) + RegisterMapping32LookupTable[index].Offset));
	}
	else
	{
		return FormatInt64HexUpper(*(__int64*)((BYTE*)(&(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Context64) + RegisterMapping64LookupTable[index].Offset));
	}
#else
	return FormatHexadecimalIntSpecial(*(LONG*)((BYTE*)(&(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.Context86) + RegisterMapping32LookupTable[index].Offset));
#endif
}

// ---------------------------------------------------------------------------------------------

// CryDebuggerHitView default constructor.
CryDebuggerHitView::CryDebuggerHitView()
{
	*this
		<< this->mAccessedAddress.SetColor(LtRed()).HSizePos(0, 0).TopPos(0, 30)
		<< this->mRegisterView.HSizePos(0, 0).VSizePos(30, 0)
	;
	
	this->mAccessedAddress.WhenLeftUp = THISBACK(HitInstructionClicked);
	
	this->mRegisterView.CryAddRowNumColumn("Register", 40).SetConvert(Single<IndexBasedValueConvert<GetRegisterName>>());
	this->mRegisterView.CryAddRowNumColumn("Value", 60).SetConvert(Single<IndexBasedValueConvert<GetRegisterValue>>());
	
	this->disasmAddress = 0;
}

// CryDebuggerHitView default destructor.
CryDebuggerHitView::~CryDebuggerHitView()
{
	
}

// Sets the instruction string that is displayed in the underlying label.
void CryDebuggerHitView::SetInstructionString(const SIZE_T is)
{
	// Do nothing if the instruction is empty. This happens in the initialization situation.
	if (!is)
	{
		return;
	}
	
	this->disasmAddress = is;
	
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		this->mAccessedAddress.SetLabel(Format("%lX - %s", (LONG_PTR)is, DisasmGetLine(is, ARCH_X86, NULL)));
	}
	else
	{
		this->mAccessedAddress.SetLabel(Format("%llX - %s", (LONG_PTR)is, DisasmGetLine(is, ARCH_X64, NULL)));
	}
#else
	this->mAccessedAddress.SetLabel(Format("%lX - %s", (LONG_PTR)is, DisasmGetLine(is, ARCH_X86, NULL)));
#endif
}

// Clears the instruction string that is displayed in the underlying label.
void CryDebuggerHitView::ClearInstructionString()
{
	this->mAccessedAddress.Clear();
}

// Sets the tooltip text for the underlying label.
void CryDebuggerHitView::SetTooltip(const char* tt)
{
	this->mAccessedAddress.SetTooltip(tt);
}

// Proxy function to pass the count through to the custom control.
void CryDebuggerHitView::SetRegisterCount(const int count)
{
	if (!count)
	{
		this->mRegisterView.Clear();
	}
	else
	{
		this->mRegisterView.SetVirtualCount(count);
	}
}

// Function is executed when the instruction label is clicked. Should link to the disassemly window.
void CryDebuggerHitView::HitInstructionClicked()
{
	if (this->disasmAddress)
	{
		// Selects the disassembly window to be active and jumps to the hit instruction.
		mCrySearchWindowManager->GetDisasmWindow()->MoveToAddress(this->disasmAddress);
		mCrySearchWindowManager->GetParentWindow()->SetActiveTabWindow("Disassembly");
	}
}