#include "CrashHandler.h"
#include "FrontendGlobalDef.h"
#include "BackendGlobalDef.h"

#include <VerRsrc.h>
#include <DbgHelp.h>

// ---------------------------------------------------------------------------------------------

CryCrashHandlerWindow::CryCrashHandlerWindow(const String& excMsg)
{
	this->Title("Crash Report").Sizeable().SetRect(0, 0, 600, 300);
	
	*this
		<< this->mErrorImage.SetImage(CtrlImg::error()).LeftPos(10, 50).TopPos(10, 50)
		<< this->mDescriptionLabel.SetLabel("An error has occured inside CrySearch. The information\r\nin this crash report can be used to inform the developer\r\nabout a bug or malfunction.").HSizePos(70, 5).TopPos(10, 60)
		<< this->mCrashReport.SetEditable(false).HSizePos(5, 5).VSizePos(70, 35)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 60).BottomPos(5, 25)
		<< this->mCopyToClipboard.SetLabel("Copy to Clipboard").RightPos(70, 125).BottomPos(5, 25)
	;
	
	this->mOk <<= THISBACK(CloseWindow);
	this->mCopyToClipboard <<= THISBACK(CopyCrashReport);
	
	this->mDescriptionLabel.SetVAlign(ALIGN_TOP);
	this->mCrashReport.Set(excMsg);
	
	// an error stays an error, the beep is a nice addition.
	BeepExclamation();
}

CryCrashHandlerWindow::~CryCrashHandlerWindow()
{
	
}

void CryCrashHandlerWindow::CopyCrashReport()
{
	WriteClipboardText(this->mCrashReport.Get());
}

void CryCrashHandlerWindow::CloseWindow()
{
	this->Close();
}

// ---------------------------------------------------------------------------------------------

// Handles exceptions that are not caught just before the application crashes.
LONG __stdcall CrashHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// Parse exception information.
	const PEXCEPTION_RECORD exc = ExceptionInfo->ExceptionRecord;
	const ULONG_PTR reason = exc->ExceptionInformation[0];
	const LONG_PTR addr = exc->ExceptionInformation[1];
	
	// Start off with the crash report string.
	char versionString[256];
	GetOSVersionString(versionString, 256);
	String excMsg(versionString);
	excMsg += "\r\n\r\nException Information:\r\n\r\n";
	
	// Access violations are the most common and should be handled as detailedly as possible.
	excMsg += "Exception:\t\t\t";
	if (exc->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		excMsg += "Access violation ";
		if (reason == 0)
		{
			// Access violation reading.
#ifdef _WIN64
			excMsg += Format("reading location %llX\r\n", addr);
#else
			excMsg += Format("reading location %lX\r\n", addr);
#endif
		}
		else if (reason == 1)
		{
			// Access violation writing.
#ifdef _WIN64
			excMsg += Format("writing location %llX\r\n", addr);
#else
			excMsg += Format("writing location %lX\r\n", addr);
#endif
		}
		else if (reason == 8)
		{
			// Data Execution Prevention access violation.
#ifdef _WIN64
			excMsg += Format("executing location %llX\r\n", addr);
#else
			excMsg += Format("executing location %lX\r\n", addr);
#endif
		}
		else
		{
			// Unknown access violation exception.
#ifdef _WIN64
			excMsg += Format("at location %llX\r\n", addr);
#else
			excMsg += Format("at location %lX\r\n", addr);
#endif
		}
	}
	else
	{
		excMsg += ParseExceptionCode(exc->ExceptionCode);
	}
	
	// Add the call stack to the crash report.
	HANDLE hCur = GetCurrentProcess();
	SymInitialize(hCur, NULL, TRUE);
	
	Vector<Win32StackTraceEntry> callstack;
	
#ifdef _WIN64
	ConstructStackTrace(hCur, IMAGE_FILE_MACHINE_AMD64, ExceptionInfo->ContextRecord, callstack);
#else
	ConstructStackTrace(hCur, IMAGE_FILE_MACHINE_I386, ExceptionInfo->ContextRecord, callstack);
#endif

	SymCleanup(hCur);
	
	excMsg += "\r\nStack Trace:\r\n\r\n";
	if (!callstack.GetCount())
	{
		excMsg += "Failed to obtain the stack trace for the exception!";
	}
	
	// Iterate the obtained stack trace.
	for (int i = 0; i < callstack.GetCount(); ++i)
	{
		excMsg += callstack[i].StringRepresentation + "\r\n";
	}
	
	// Pop up crash report window.
	CryCrashHandlerWindow* cchw = new CryCrashHandlerWindow(excMsg);
	cchw->Execute();
	delete cchw;
	
	// Let the exception run into the next exception handler.
	return EXCEPTION_EXECUTE_HANDLER;
}