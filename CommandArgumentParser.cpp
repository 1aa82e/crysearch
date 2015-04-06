#include "CommandArgumentParser.h"
#include "CrySearchLibrary/SDK/CrySearch.h"

CommandArgumentParser::CommandArgumentParser(const Vector<String>& args)
{
	this->wasShellExec = false;
	this->showHelp = false;
	this->parameterCount = args.GetCount();
	this->procId = 0;
	this->options = 0;
	
	// Parse the command line arguments to internal variables.
	this->Parse(args);
}

CommandArgumentParser::~CommandArgumentParser()
{
	
}

// Parses the command line arguments.
void CommandArgumentParser::Parse(const Vector<String>& args)
{
	// Check whether CrySearch was started using a shell execution from an associated file extension.
	const int argc = args.GetCount();
	if (argc > 0 && FileExists(args[0]))
	{
		this->wasShellExec = true;
		return;
	}
	
	// Walk the arguments.
	for (int i = 0; i < argc; ++i)
	{
		if (args[i] == "-h" || args[i] == "?" || args[i] == "--help")
		{
			this->showHelp = true;
			break;
		}
		else if ((args[i] == "-p" || args[i] == "--pid") && i + 1 < argc)
		{
			this->procId = StrInt(args[++i]);
		}
		else if ((args[i] == "-f" || args[i] == "--filename") && i + 1 < argc)
		{
			this->filePath = args[++i];
		}
		else if ((args[i] == "-o" || args[i] == "--options") && i + 1 < argc)
		{
			for (int o = i + 1; o < argc && !args[o].StartsWith("-"); ++o)
			{
				if (args[o] == "all")
				{
					this->options = CRYSEARCH_COMMAND_OPTION_PE | CRYSEARCH_COMMAND_OPTION_IMPORTS | CRYSEARCH_COMMAND_OPTION_THREADS | CRYSEARCH_COMMAND_OPTION_MODULES;
					break;
				}
				else if (args[o] == "pe")
				{
					this->options |= CRYSEARCH_COMMAND_OPTION_PE;
				}
				else if (args[o] == "imports")
				{
					this->options |= CRYSEARCH_COMMAND_OPTION_IMPORTS;
				}
				else if (args[o] == "threads")
				{
					this->options |= CRYSEARCH_COMMAND_OPTION_THREADS;
				}
				else if (args[o] == "modules")
				{
					this->options |= CRYSEARCH_COMMAND_OPTION_MODULES;
				}
			}
		}
		else if ((args[i] == "-w" || args[i] == "--write") && i + 1 < argc)
		{
			this->outputFile = args[++i];
		}
	}
}

// ---------------------------------------------------------------------------------------------

// Gets the amount of entered parameters.
const int CommandArgumentParser::GetParameterCount() const
{
	return this->parameterCount;
}

// Provides help output for the CrySearch command line.
String CommandArgumentParser::GetHelpOutput() const
{
	// Retrieve the current CrySearch version.
	WORD major;
	WORD minor;
	CrySearchGetMajorMinorVersion(&major, &minor);
	
	// Obfuscated strings for the output.
	DWORD wndTitle[] = {0x53797243, 0x63726165, 0x654d2068, 0x79726f6d, 0x61635320, 0x72656e6e, 0x0}; //"CrySearch Memory Scanner"
	DWORD author[] = {0x6c6f7665, 0x6f697475, 0x3633356e, 0x0}; //"evolution536"
	
	String appname((char*)wndTitle, 9);
	return Format("%s v%i.%i by %s\r\n\r\nUsage:\t%s file_name\r\n\t%s [options]\r\n\r\nOptions:\t?, -h, --help\tShows this help menu\r\n"\
					"\t-p, --pid <pid>\tSelects process ID to operate on\r\n\t-f, --filename <fn>\tCreates process from file\r\n"\
					"\t-o, --options <opt>\tSpecifies options to execute\r\n\tPossible options: all pe imports threads modules\r\n"\
					"\t-w, --write <file>\tSpecifies file to write output to", (char*)wndTitle, major, minor, (char*)author, appname, appname);
}

// Returns whether CrySearch was opened with a shell execution for an associated file.
const bool CommandArgumentParser::GetWasShellExecuted() const
{
	return this->wasShellExec;
}

// Gets whether the user executed a help command.
const bool CommandArgumentParser::WasHelpCommandFound() const
{
	return this->showHelp;
}

// Gets the process ID that was entered as argument. Returns 0 if no process ID was entered.
const DWORD CommandArgumentParser::GetProcessId() const
{
	return this->procId;
}

// Gets the file path that was entered as argument. Returns an empty string if no file path was entered.
const String& CommandArgumentParser::GetFilePath() const
{
	return this->filePath;
}

// Gets the options that were specified in the command line option (-o, --options).
const DWORD CommandArgumentParser::GetOptions() const
{
	return this->options;
}

// Gets the filename of the output file, which to write any output to.
const String& CommandArgumentParser::GetOutputFile() const
{
	return this->outputFile;
}