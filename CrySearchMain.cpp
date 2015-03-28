#include "CrySearchForm.h"
#include "CommandArgumentParser.h"
#include "CrashHandler.h"
#include "BackendGlobalDef.h"
#include "FrontendGlobalDef.h"

// Runs the CrySearch application, initializing the main window.
void RunApplication(CrySearchForm* mainWindow)
{
	// Delete temporary files from any earlier run, which might have crashed.
	DeleteTemporaryFiles();
	
	// Run main window.
	mCrySearchWindowManager = mainWindow->GetWindowManager();
	mainWindow->Run();
	delete mainWindow;
}

// Finalizes the CrySearch application when the main window is destroyed.
void FinalizeApplication()
{
	// Force destruction of global objects to restore states of opened processes.
	CryGlobalDestruct();
	
	// Release the memory scanner and other related resources.
	delete GlobalScanParameter;

	// Delete temporary files used before quitting.
	DeleteTemporaryFiles();
}

// CrySearch application entrypoint function. It executes global operations.
GUI_APP_MAIN
{
	// Initialize CrySearch main component.
	mMemoryScanner = MemoryScanner::GetInstance();
	CrySearchForm* frm;
	
	// Wire up the crash handler.
	SetUnhandledExceptionFilter(CrashHandler);
	
	// Get the command line. In case a .csat file was opened, the first argument is the path to the file.
	const Vector<String>& cmdline = CommandLine();
	CommandArgumentParser cmdParser(cmdline);
	if (cmdParser.GetWasShellExecuted())
	{
		frm = new CrySearchForm(cmdline[0]);
		RunApplication(frm);
		FinalizeApplication();
	}
	else
	{
		// Regularly parse command line arguments.
		if (cmdParser.GetParameterCount())
		{
			int pid;
			
			// If the help command was executed, don't continue the application but output help.
			if (cmdParser.WasHelpCommandFound())
			{
				MessageBox(NULL, cmdParser.GetHelpOutput(), "Help", MB_ICONINFORMATION);
			}
			else
			{
				// Try to open a process by using a PID or create one using the filename specified by a command line parameter.
				if (cmdParser.GetProcessId())
				{
					if (!mMemoryScanner->InitializeExistingProcess(cmdParser.GetProcessId(), ""))
					{
						MessageBox(NULL, "Failed to initialize the process!", "Fatal Error", MB_ICONERROR);
					}
				}
				else if (cmdParser.GetFilePath().IsEmpty() || !mMemoryScanner->InitializeNewProcess(cmdParser.GetFilePath(), 0, 0, &pid))
				{
					MessageBox(NULL, "Failed to initialize the process!", "Fatal Error", MB_ICONERROR);
				}
				
				// Clean up opened process if any.
				mMemoryScanner->CloseProcess();
			}
		}
		else
		{
			// No parameters were found, execute program regularly.
			frm = new CrySearchForm(NULL);
			RunApplication(frm);
			FinalizeApplication();
		}
	}

	// Close all threads to make the application able to exit safely.
	ExitProcess(0);
}