#include "CrashHandler.h"
#include "FrontendGlobalDef.h"
#include "BackendGlobalDef.h"

#include <VerRsrc.h>
#include <DbgHelp.h>

// ---------------------------------------------------------------------------------------------

// The CryCrashHandlerWindow default constructor.
CryCrashHandlerWindow::CryCrashHandlerWindow(const String& excMsg)
{
	this->Title("Crash Report").Sizeable().SetRect(0, 0, 600, 300);
	
	*this
		<< this->mErrorImage.SetImage(CtrlImg::error()).LeftPos(10, 50).TopPos(10, 50)
		<< this->mDescriptionLabel.SetLabel("An error has occured inside CrySearch. The information\r\nin this crash report can be used to inform the developer\r\nabout a bug or malfunction.").HSizePos(70, 5).TopPos(10, 60)
		<< this->mCrashReport.SetEditable(false).HSizePos(5, 5).VSizePos(70, 35)
		<< this->mOk.Ok().SetLabel("OK").RightPos(5, 70).BottomPos(5, 25)
		<< this->mCopyToClipboard.SetLabel("Copy to Clipboard").LeftPos(5, 150).BottomPos(5, 25)
	;
	
	this->mOk <<= THISBACK(CloseWindow);
	this->mCopyToClipboard <<= THISBACK(CopyCrashReport);
	
	this->mDescriptionLabel.SetVAlign(ALIGN_TOP);
	this->mCrashReport.Set(excMsg);
	
	// an error stays an error, the beep is a nice addition.
	BeepExclamation();
}

// The CryCrashHandlerWindow default destructor.
CryCrashHandlerWindow::~CryCrashHandlerWindow()
{
	
}

// Copies the content of the crash report.
void CryCrashHandlerWindow::CopyCrashReport()
{
	WriteClipboardText(this->mCrashReport.Get());
}

// Executed when the crash handler window is closed.
void CryCrashHandlerWindow::CloseWindow()
{
	this->Close();
}

// Finds information about a loaded module by its address.
const Win32ModuleInformation* FindLocalModuleAddress(const Vector<Win32ModuleInformation>& mods, const SIZE_T current)
{
	const int modCount = mods.GetCount();
	for (int i = 0; i < modCount; ++i)
	{
		const Win32ModuleInformation& curMod = mods[i];
		if (current >= curMod.BaseAddress && current < curMod.BaseAddress + curMod.Length)
		{
			return &curMod;
		}
	}
	
	// The module was not found, so no information is returned.
	return NULL;
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
	
	Vector<DWORD64> callstack;
	
#ifdef _WIN64
	ConstructStackTrace(hCur, IMAGE_FILE_MACHINE_AMD64, ExceptionInfo->ContextRecord, callstack);
#else
	ConstructStackTrace(hCur, IMAGE_FILE_MACHINE_I386, ExceptionInfo->ContextRecord, callstack);
#endif
	
	excMsg += "\r\nStack Trace:\r\n\r\n";
	if (!callstack.GetCount())
	{
		excMsg += "Failed to obtain the stack trace for the exception!";
	}
	
	// Retrieve a locally loaded module list to trace back the exception through modules.
	Vector<Win32ModuleInformation> localMods;
	ModuleManager::EnumerateModules(GetCurrentProcessId(), localMods);
	
	// Iterate the obtained stack trace.
	const int count = callstack.GetCount();
	for (int i = 0; i < count; ++i)
	{
		const DWORD64& current = callstack[i];
		const Win32ModuleInformation* mod = NULL;
		if (mod = FindLocalModuleAddress(localMods, (SIZE_T)current))
		{
			// Retrieve the module name of the local module that caused the exception.
			StringBuffer buffer(MAX_PATH);
			GetModuleFileName((HMODULE)mod->BaseAddress, buffer.Begin(), MAX_PATH);
			buffer.Strlen();
			String modName = GetFileNamePos(buffer.Begin());
			
			// Retrieve the name of a symbol that is related to the call stack entry.
			char symbolName[MAX_PATH];
			if (GetSingleSymbolName(hCur, (SIZE_T)current, symbolName, MAX_PATH))
			{
				excMsg += Format("%s!%s\r\n", modName, symbolName);
			}
			else
			{
				excMsg += Format("%s!%llX\r\n", modName, (LONG_PTR)current);
			}
		}
		else
		{
			excMsg += Format("%llX\r\n", (LONG_PTR)current);
		}
	}
	
	SymCleanup(hCur);
	
	// Pop up crash report window.
	if (Thread::IsMain())
	{
		CryCrashHandlerWindow* cchw = new CryCrashHandlerWindow(excMsg);
		cchw->Execute();
		delete cchw;
	}
	else
	{
		// It was not the main thread that caused the exception. Dispatch the handling of it to
		// the main thread and wait for it to complete.
		mCrySearchWindowManager->GetParentWindow()->ExecuteCrashHandlerWindow(excMsg);
	}
	
	// Let the exception run into the next exception handler.
	return EXCEPTION_EXECUTE_HANDLER;
}