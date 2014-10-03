#include "CrashHandler.h"
#include "GlobalDef.h"

#include <VerRsrc.h>
#include <DbgHelp.h>

// ---------------------------------------------------------------------------------------------

CryCrashHandlerWindow::CryCrashHandlerWindow(const String& excMsg)
{
	this->Title("Crash Report").Sizeable().SetRect(0, 0, 600, 300);
	
	*this
		<< this->mErrorImage.SetImage(CtrlImg::error()).LeftPos(10, 50).TopPos(10, 50)
		<< this->mDescriptionLabel.SetLabel("An error has occured inside CrySearch. The information\r\nin this crash report can be used to inform the developer\r\nabout a bug or malfunction.").HSizePos(60, 5).TopPos(10, 60)
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

// Retrieves information about the operating system for a crash report.
String GetOSVersionString()
{
	// Retrieve OS information.
	OSVERSIONINFOEX osv;
	osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osv);
	
	String verReturn = "System Information:\r\n\r\nOS Version:\t\t\t";
	
	// Parse version numbers into a version string for the crash report.
	if (osv.dwMajorVersion == 6)
	{
		if (osv.dwMinorVersion == 3)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				verReturn += "Windows 8.1";
			}
			else
			{
				verReturn += "Windows Server 2012 R2";
			}
		}
		else if (osv.dwMinorVersion == 2)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				verReturn += "Windows 8";
			}
			else
			{
				verReturn += "Windows Server 2012";
			}
		}
		else if (osv.dwMinorVersion == 1)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				verReturn += "Windows 7";
			}
			else
			{
				verReturn += "Windows Server 2008 R2";
			}			
		}
		else if (osv.dwMinorVersion == 0)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				verReturn += "Windows Vista";
			}
			else
			{
				verReturn += "Windows Server 2008";
			}			
		}
	}
	else if (osv.dwMajorVersion == 5)
	{
		if (osv.dwMinorVersion == 2)
		{
			if (GetSystemMetrics(SM_SERVERR2) == 0)
			{
				verReturn += "Windows Server 2003";
			}
			else
			{
				verReturn += "Windows Server 2003 R2";
			}
		}
		else if (osv.dwMinorVersion == 1)
		{
			verReturn += "Windows XP";
		}
	}
	
	// Add the OS architecture to the crash report.
	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);
	verReturn += "\r\nArchitecture:\t\t";
	verReturn += sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "x64";
	
	// Add CrySearch architecture definition.
#ifdef _WIN64
	verReturn += "\r\nCrySearch:\t\t\t";
	if (IsI386Process(GetCurrentProcess()))
	{
		verReturn += "x86";
	}
	else
	{
		verReturn += "x64";
	}
#else
	verReturn += "\r\nCrySearch:\t\t\tx86";
#endif
	
	verReturn += "\r\n";
	return verReturn;
}

// Handles exceptions that are not caught just before the application crashes.
LONG __stdcall CrashHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	// Parse exception information.
	const PEXCEPTION_RECORD exc = ExceptionInfo->ExceptionRecord;
	const ULONG_PTR reason = exc->ExceptionInformation[0];
	const LONG_PTR addr = exc->ExceptionInformation[1];
	
	// Start off with the crash report string.
	String excMsg = GetOSVersionString();
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