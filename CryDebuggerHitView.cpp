#include "CryDebuggerHitView.h"
#include "CrySearchForm.h"
#include "GlobalDef.h"

// The breakpoint master index is needed in both classes so externally declared here.
extern int BreakpointMasterIndex;

// Describes a register in a debugger breakpoint snapshot.
struct RegisterNameOffsetMapping
{
	char Name[4];
	DWORD Offset;
};

#ifdef _WIN64
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

String GetRegisterValue(const int index)
{
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		return Format("%lX", *(LONG*)((BYTE*)(&((CryThreadContext<WOW64_CONTEXT>*)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.ThreadContextContainer)->ThreadContext) + RegisterMapping32LookupTable[index].Offset));
	}
	else
	{
		return Format("%llX", *(__int64*)((BYTE*)(&((CryThreadContext<CONTEXT>*)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.ThreadContextContainer)->ThreadContext) + RegisterMapping64LookupTable[index].Offset));
	}
#else
	return Format("%lX", *(LONG*)((BYTE*)(&((CryThreadContext<CONTEXT>*)(*mDebugger)[BreakpointMasterIndex].BreakpointSnapshot.ThreadContextContainer)->ThreadContext) + RegisterMapping32LookupTable[index].Offset));
#endif
}

// ---------------------------------------------------------------------------------------------

CryDebuggerHitView::CryDebuggerHitView()
{
	*this
		<< this->mAccessedAddress.SetColor(LtRed()).HSizePos(0, 0).TopPos(0, 30)
		<< this->mRegisterView.HSizePos(0, 0).VSizePos(30, 0)
	;
	
	this->mAccessedAddress.WhenLeftUp = THISBACK(HitInstructionClicked);
	
	this->mRegisterView.AddRowNumColumn("Register", 40).SetConvert(Single<IndexBasedValueConvert<GetRegisterName>>());
	this->mRegisterView.AddRowNumColumn("Value", 60).SetConvert(Single<IndexBasedValueConvert<GetRegisterValue>>());
	
	this->disasmAddress = 0;
}

CryDebuggerHitView::~CryDebuggerHitView()
{
	
}

// Sets the instruction string that is displayed in the underlying label.
void CryDebuggerHitView::SetInstructionString(const DisasmLine& is)
{
	// Do nothing if the instruction is empty. This happens in the initialization situation.
	if (!is.VirtualAddress)
	{
		return;
	}
	
	this->disasmAddress = is.VirtualAddress;
	
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		this->mAccessedAddress.SetLabel(Format("%lX - %s", is.VirtualAddress, is.InstructionLine));
	}
	else
	{
		this->mAccessedAddress.SetLabel(Format("%llX - %s", is.VirtualAddress, is.InstructionLine));
	}
#else
	this->mAccessedAddress.SetLabel(Format("%lX - %s", is.VirtualAddress, is.InstructionLine));
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
	this->mRegisterView.SetVirtualCount(count);
}

// Function is executed when the instruction label is clicked. Should link to the disassemly window.
void CryDebuggerHitView::HitInstructionClicked()
{
	if (this->disasmAddress)
	{
		extern CrySearchForm* frm;
		frm->GetDisasmWindow()->MoveToAddress(this->disasmAddress);
		frm->SetActiveTabWindow("Disassembly");
	}
}