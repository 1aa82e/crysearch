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

// Creates an output format for a thread, outputting a function name where possible.
String FormatThreadEntryOutput(const SIZE_T address)
{
	// Check whether the thread address is inside an existing module.
	const Win32ModuleInformation* mod = NULL;
	if (mod = mModuleManager->GetModuleFromContainedAddress(address))
	{
		String modName = mModuleManager->GetModuleFilename(mod->BaseAddress);
#ifdef _WIN64
		if (mMemoryScanner->IsX86Process())
		{
			return Format("%s!%lX", modName, (int)address);
		}
		else
		{
			return Format("%s!%llX", modName, (__int64)address);
		}
#else
		return Format("%s!%lX", modName, (int)address);
#endif
	}
	else
	{
		// No module information could be found, just output the start address.
#ifdef _WIN64
		if (mMemoryScanner->IsX86Process())
		{
			return FormatHexadecimalIntSpecial((int)address);
		}
		else
		{
			return FormatInt64HexUpper((__int64)address);
		}
#else
		return FormatHexadecimalIntSpecial((int)address);
#endif
	}
}

// Parses argument options and dispatches tasks accordingly. This function is for 32-bit processes.
void DispatchOptionsOperation32(const DWORD options, FileOut& outStream)
{
	outStream << Format("Analysis output for %s at PID: %i\r\n\r\n", mMemoryScanner->GetProcessName(), mMemoryScanner->GetProcessId());
	
	// Do generic initialization work. Some components must be initialized before using any other.
	CrySearchRoutines.InitializeRoutines();
	mModuleManager = ModuleManager::GetInstance();
	mModuleManager->Initialize();
	mPeInstance = new PortableExecutable32();
	
	// Parse specified options.
	if (options & CRYSEARCH_COMMAND_OPTION_PE)
	{
		// Get the PE headers of the process executable.
		if (mModuleManager->GetModuleCount() > 0)
		{
			mPeInstance->GetExecutablePeInformation();

			int nextCount = LoadedProcessPEInformation.PEFields.GetCount();
			int i = 0;
			outStream << "PE Header\r\n--------------------------------------------------\r\n";
			for (; i < nextCount; ++i)
			{
				const String& key = LoadedProcessPEInformation.PEFields.GetKey(i);
				outStream << Format("%s: %s\r\n", key, LoadedProcessPEInformation.PEFields.Get(key).ToString());
			}
			
			nextCount = LoadedProcessPEInformation.ImageSections.GetCount();
			outStream << "\r\nPE Sections\r\n--------------------------------------------------\r\n";
			for (i = 0; i < nextCount; ++i)
			{
				const Win32PESectionInformation& section = LoadedProcessPEInformation.ImageSections[i];
				outStream << Format("%s\tOffset: %lX - Size: %lX\r\n", section.SectionName, (LONG_PTR)section.BaseAddress, (LONG_PTR)section.SectionSize);
			}
			
			nextCount = LoadedProcessPEInformation.DotNetInformation.DotNetSections.GetCount();
			// It's not certain that a process executable embeds .NET sections.
			if (nextCount)
			{
				outStream << "\r\n.NET sections\r\n--------------------------------------------------\r\n";
				for (i = 0; i < nextCount; ++i)
				{
					const Win32DotNetSectionInformation& section = LoadedProcessPEInformation.DotNetInformation.DotNetSections[i];
					outStream << Format("%s\tOffset: %lX - Size: %lX\r\n", section.SectionName, section.Offset, section.Size);
				}
			}
		}
	}
	if (options & CRYSEARCH_COMMAND_OPTION_IMPORTS)
	{
		// Get the imports of the process executable.
		mPeInstance->GetImportAddressTable();
		const int modCount = LoadedProcessPEInformation.ImportAddressTable.GetCount();
		outStream << "\r\nImport Address Table\r\n--------------------------------------------------\r\n";
		for (int m = 0; m < modCount; ++m)
		{
			const ImportTableDescriptor& desc = LoadedProcessPEInformation.ImportAddressTable[m];
			const int funcCount = desc.FunctionList.GetCount();
			outStream << Format("%s:\r\n", desc.ModuleName);
			for (int f = 0; f < funcCount; ++f)
			{
				const ImportAddressTableEntry& function = desc.FunctionList[f];
				outStream << Format("\t%s, Address: %lX, Ordinal: %i\r\n", function.FunctionName, (LONG_PTR)function.VirtualAddress, function.Ordinal);
			}
		}
	}
	if (options & CRYSEARCH_COMMAND_OPTION_THREADS)
	{
		// Get the thread list of the process executable.
		EnumerateThreads(mMemoryScanner->GetProcessId(), mThreadsList);
		const int threadCount = mThreadsList.GetCount();
		outStream << "\r\nThread list\r\n--------------------------------------------------\r\n";
		for (int i = 0; i < threadCount; ++i)
		{
			const Win32ThreadInformation& curThread = mThreadsList[i];
			outStream << Format("Start Address: %s, Thread ID: %i\r\n", FormatThreadEntryOutput(curThread.StartAddress), curThread.ThreadIdentifier);
		}
	}
	if (options & CRYSEARCH_COMMAND_OPTION_MODULES)
	{
		// Get the module list of the process executable.
		const int modCount = mModuleManager->GetModuleCount();
		outStream << "\r\nModule list\r\n--------------------------------------------------\r\n";
		for (int i = 0; i < modCount; ++i)
		{
			const Win32ModuleInformation& curMod = (*mModuleManager)[i];
			outStream << Format("%s, Base Address: %lX, Size: %lX\r\n", mModuleManager->GetModuleFilename(curMod.BaseAddress), (LONG_PTR)curMod.BaseAddress, curMod.Length);
		}
	}
	
	delete mPeInstance;
}

#ifdef _WIN64
	// Parses argument options and dispatches tasks accordingly. This function is for 64-bit processes.
	void DispatchOptionsOperation64(const DWORD options, FileOut& outStream)
	{
		outStream << Format("Analysis output for %s at PID: %i\r\n\r\n", mMemoryScanner->GetProcessName(), mMemoryScanner->GetProcessId());
		
		// Do generic initialization work. Some components must be initialized before using any other.
		CrySearchRoutines.InitializeRoutines();
		mModuleManager = ModuleManager::GetInstance();
		mModuleManager->Initialize();
		mPeInstance = new PortableExecutable64();
		
		// Parse specified options.
		if (options & CRYSEARCH_COMMAND_OPTION_PE)
		{
			// Get the PE headers of the process executable.
			if (mModuleManager->GetModuleCount() > 0)
			{
				mPeInstance->GetExecutablePeInformation();
				
				int nextCount = LoadedProcessPEInformation.PEFields.GetCount();
				int i = 0;
				outStream << "PE Header\r\n--------------------------------------------------\r\n";
				for (; i < nextCount; ++i)
				{
					const String& key = LoadedProcessPEInformation.PEFields.GetKey(i);
					outStream << Format("%s: %s\r\n", key, LoadedProcessPEInformation.PEFields.Get(key).ToString());
				}
				
				nextCount = LoadedProcessPEInformation.ImageSections.GetCount();
				outStream << "\r\nPE Sections\r\n--------------------------------------------------\r\n";
				for (i = 0; i < nextCount; ++i)
				{
					const Win32PESectionInformation& section = LoadedProcessPEInformation.ImageSections[i];
					outStream << Format("%s\tOffset: %llX - Size: %llX\r\n", section.SectionName, (LONG_PTR)section.BaseAddress, (LONG_PTR)section.SectionSize);
				}
				
				nextCount = LoadedProcessPEInformation.DotNetInformation.DotNetSections.GetCount();
				// It's not certain that a process executable embeds .NET sections.
				if (nextCount)
				{
					outStream << "\r\n.NET sections\r\n--------------------------------------------------\r\n";
					for (i = 0; i < nextCount; ++i)
					{
						const Win32DotNetSectionInformation& section = LoadedProcessPEInformation.DotNetInformation.DotNetSections[i];
						outStream << Format("%s\tOffset: %lX - Size: %lX\r\n", section.SectionName, section.Offset, section.Size);
					}
				}
			}
		}
		if (options & CRYSEARCH_COMMAND_OPTION_IMPORTS)
		{
			// Get the imports of the process executable.
			mPeInstance->GetImportAddressTable();
			const int modCount = LoadedProcessPEInformation.ImportAddressTable.GetCount();
			outStream << "\r\nImport Address Table\r\n--------------------------------------------------\r\n";
			for (int m = 0; m < modCount; ++m)
			{
				const ImportTableDescriptor& desc = LoadedProcessPEInformation.ImportAddressTable[m];
				const int funcCount = desc.FunctionList.GetCount();
				outStream << Format("%s:\r\n", desc.ModuleName);
				for (int f = 0; f < funcCount; ++f)
				{
					const ImportAddressTableEntry& function = desc.FunctionList[f];
					outStream << Format("\t%s, Address: %llX, Ordinal: %i\r\n", function.FunctionName, (LONG_PTR)function.VirtualAddress, function.Ordinal);
				}
			}
		}
		if (options & CRYSEARCH_COMMAND_OPTION_THREADS)
		{
			// Get the thread list of the process executable.
			EnumerateThreads(mMemoryScanner->GetProcessId(), mThreadsList);
			const int threadCount = mThreadsList.GetCount();
			outStream << "\r\nThread list\r\n--------------------------------------------------\r\n";
			for (int i = 0; i < threadCount; ++i)
			{
				const Win32ThreadInformation& curThread = mThreadsList[i];
				outStream << Format("Start Address: %s, Thread ID: %i\r\n", FormatThreadEntryOutput(curThread.StartAddress), curThread.ThreadIdentifier);
			}
		}
		if (options & CRYSEARCH_COMMAND_OPTION_MODULES)
		{
			// Get the module list of the process executable.
			const int modCount = mModuleManager->GetModuleCount();
			outStream << "\r\nModule list\r\n--------------------------------------------------\r\n";
			for (int i = 0; i < modCount; ++i)
			{
				const Win32ModuleInformation& curMod = (*mModuleManager)[i];
				outStream << Format("%s, Base Address: %llX, Size: %llX\r\n", mModuleManager->GetModuleFilename(curMod.BaseAddress), (LONG_PTR)curMod.BaseAddress, curMod.Length);
			}
		}
		
		delete mPeInstance;
	}
#endif

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
				MessageBox(NULL, CommandArgumentParser::GetHelpOutput(), "Help", MB_ICONINFORMATION);
			}
			else
			{
				// Check if the user specified an output file to write to. If not, abort. Output must be written somewhere.
				const String& file = cmdParser.GetOutputFile();
				if (file.IsEmpty())
				{
					MessageBox(NULL, "An output file must be specified!", "Fatal Error", MB_ICONERROR);
				}
				else
				{
					FileOut outputStream;
					
					// If the output file exists, delete it in advance.
					if (FileExists(file))
					{
						DeleteFile(file);
					}
					
					outputStream.Open(file);
					
					// Retrieve the current CrySearch version.
					WORD major;
					WORD minor;
					CrySearchGetMajorMinorVersion(&major, &minor);
					
					DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
					DWORD author[] = {0x6c6f7665, 0x6f697475, 0x3633356e, 0x0}; //"evolution536"
					outputStream << Format("%s v%i.%i by %s\r\n\r\n", (char*)wndTitle, major, minor, (char*)author);
					
					// Try to open a process by using a PID or create one using the filename specified by a command line parameter.
					if (cmdParser.GetProcessId())
					{
						// In addition to opening the process using the memory scanner, we need to explicitly check
						// whether the process is still active (f.e. not a zombie). OpenProcess will succeed even if
						// the process has already closed, until the last handle to it has been closed.
						if (mMemoryScanner->InitializeExistingProcess(cmdParser.GetProcessId(), NULL, false) && IsProcessActive(mMemoryScanner->GetHandle()))
						{
#ifdef _WIN64
							if (mMemoryScanner->IsX86Process())
							{
								DispatchOptionsOperation32(cmdParser.GetOptions(), outputStream);
							}
							else
							{
								DispatchOptionsOperation64(cmdParser.GetOptions(), outputStream);
							}
#else
							DispatchOptionsOperation32(cmdParser.GetOptions(), outputStream);
#endif
						}
						else
						{
							MessageBox(NULL, "Failed to initialize the process!", "Fatal Error", MB_ICONERROR);
							outputStream << "Failed to initialize the process!";
						}
					}
					else if (!cmdParser.GetFilePath().IsEmpty())
					{
						if (mMemoryScanner->InitializeNewProcess(cmdParser.GetFilePath(), 0, 0, &pid))
						{
#ifdef _WIN64
							if (mMemoryScanner->IsX86Process())
							{
								DispatchOptionsOperation32(cmdParser.GetOptions(), outputStream);
							}
							else
							{
								DispatchOptionsOperation64(cmdParser.GetOptions(), outputStream);
							}
#else
							DispatchOptionsOperation32(cmdParser.GetOptions(), outputStream);
#endif
						}
						else
						{
							MessageBox(NULL, "Failed to initialize the process!", "Fatal Error", MB_ICONERROR);
							outputStream << "Failed to initialize the process!";
						}
					}
					else
					{
						MessageBox(NULL, "Please enter a PID or filename as argument!", "Input Error", MB_ICONERROR);
					}
					
					// Clean up opened process if any.
					mMemoryScanner->CloseProcess();
				}
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