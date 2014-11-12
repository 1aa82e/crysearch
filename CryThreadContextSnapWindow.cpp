#include "CryThreadContextSnapWindow.h"
#include "GlobalDef.h"

CryThreadContextSnapWindow::CryThreadContextSnapWindow(const Image& icon, const int threadId) : CryDialogTemplate(icon)
{
	this->mThreadId = threadId;
	
	this->Title(Format("Context snapshot of thread %X", threadId)).SetRect(0, 0, 300, 300);
	this->mRefresh <<= THISBACK(RefreshSnapshot);
	this->mClose <<= THISBACK(CloseWindow);
	
	*this
		<< this->mContextValues.HSizePos(5, 5).VSizePos(5, 35)
		<< this->mRefresh.SetLabel("Refresh").RightPos(70, 60).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 60).BottomPos(5, 25)
	;
	
	this->mContextValues.CryAddColumn("Field");
	this->mContextValues.CryAddColumn("Value");
	
	// Load snapshot into GUI controls.
	this->RefreshSnapshot();
}

CryThreadContextSnapWindow::~CryThreadContextSnapWindow()
{
	
}

void CryThreadContextSnapWindow::RefreshSnapshot()
{
	// Clear old data.
	this->mContextValues.Clear();
	
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		WOW64_CONTEXT ctx;
		if (SnapThreadContext32(this->mThreadId, &ctx))
		{
			this->mContextValues.Add("EAX", Format("%lX", (LONG_PTR)ctx.Eax));
			this->mContextValues.Add("EBX", Format("%lX", (LONG_PTR)ctx.Ebx));
			this->mContextValues.Add("ECX", Format("%lX", (LONG_PTR)ctx.Ecx));
			this->mContextValues.Add("EDX", Format("%lX", (LONG_PTR)ctx.Edx));
			this->mContextValues.Add("EDI", Format("%lX", (LONG_PTR)ctx.Edi));
			this->mContextValues.Add("ESI", Format("%lX", (LONG_PTR)ctx.Esi));
			this->mContextValues.Add("EBP", Format("%lX", (LONG_PTR)ctx.Ebp));
			this->mContextValues.Add("ESP", Format("%lX", (LONG_PTR)ctx.Esp));
			this->mContextValues.Add("EIP", Format("%lX", (LONG_PTR)ctx.Eip));
			this->mContextValues.Add("EFlags", Format("%lX", (LONG_PTR)ctx.EFlags));
		}
		else
		{
			this->mContextValues.Add("Failed to take snapshot.");
		}
	}
	else
	{
		void* const ctxBase = VirtualAlloc(NULL, sizeof(CONTEXT) + 8, MEM_COMMIT, PAGE_READWRITE);
		PCONTEXT ctx = (PCONTEXT)ctxBase;
		AlignPointer((DWORD_PTR*)&ctx, 8);
		
		if (SnapThreadContext64(this->mThreadId, ctx))
		{
			this->mContextValues.Add("RAX", Format("%llX", (LONG_PTR)ctx->Rax));
			this->mContextValues.Add("RBX", Format("%llX", (LONG_PTR)ctx->Rbx));
			this->mContextValues.Add("RCX", Format("%llX", (LONG_PTR)ctx->Rcx));
			this->mContextValues.Add("RDX", Format("%llX", (LONG_PTR)ctx->Rdx));
			this->mContextValues.Add("RDI", Format("%llX", (LONG_PTR)ctx->Rdi));
			this->mContextValues.Add("RSI", Format("%llX", (LONG_PTR)ctx->Rsi));
			this->mContextValues.Add("RBP", Format("%llX", (LONG_PTR)ctx->Rbp));
			this->mContextValues.Add("RSP", Format("%llX", (LONG_PTR)ctx->Rsp));
			this->mContextValues.Add("RIP", Format("%llX", (LONG_PTR)ctx->Rip));
			this->mContextValues.Add("R8", Format("%llX", (LONG_PTR)ctx->R8));
			this->mContextValues.Add("R9", Format("%llX", (LONG_PTR)ctx->R9));
			this->mContextValues.Add("R10", Format("%llX", (LONG_PTR)ctx->R10));
			this->mContextValues.Add("R11", Format("%llX", (LONG_PTR)ctx->R11));
			this->mContextValues.Add("R12", Format("%llX", (LONG_PTR)ctx->R12));
			this->mContextValues.Add("R13", Format("%llX", (LONG_PTR)ctx->R13));
			this->mContextValues.Add("R14", Format("%llX", (LONG_PTR)ctx->R14));
			this->mContextValues.Add("R15", Format("%llX", (LONG_PTR)ctx->R15));
			this->mContextValues.Add("EFlags", Format("%lX", (LONG_PTR)ctx->EFlags));
		}
		else
		{
			this->mContextValues.Add("Failed to take snapshot.");
		}
		
		VirtualFree(ctxBase, 0, MEM_RELEASE);
	}
#else
	CONTEXT ctx;
	if (SnapThreadContext32(this->mThreadId, &ctx))
	{
		this->mContextValues.Add("EAX", Format("%lX", (LONG_PTR)ctx.Eax));
		this->mContextValues.Add("EBX", Format("%lX", (LONG_PTR)ctx.Ebx));
		this->mContextValues.Add("ECX", Format("%lX", (LONG_PTR)ctx.Ecx));
		this->mContextValues.Add("EDX", Format("%lX", (LONG_PTR)ctx.Edx));
		this->mContextValues.Add("EDI", Format("%lX", (LONG_PTR)ctx.Edi));
		this->mContextValues.Add("ESI", Format("%lX", (LONG_PTR)ctx.Esi));
		this->mContextValues.Add("EBP", Format("%lX", (LONG_PTR)ctx.Ebp));
		this->mContextValues.Add("ESP", Format("%lX", (LONG_PTR)ctx.Esp));
		this->mContextValues.Add("EIP", Format("%lX", (LONG_PTR)ctx.Eip));
		this->mContextValues.Add("EFlags", Format("%lX", (LONG_PTR)ctx.EFlags));
	}
	else
	{
		this->mContextValues.Add("Failed to take snapshot.");
	}
#endif
}

void CryThreadContextSnapWindow::CloseWindow()
{
	this->Close();
}