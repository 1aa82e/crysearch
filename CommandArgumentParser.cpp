#include "CommandArgumentParser.h"
#include "CrySearchLibrary/SDK/CrySearch.h"

CommandArgumentParser::CommandArgumentParser(const Vector<String>& args)
{
	this->wasShellExec = false;
	this->showHelp = false;
	this->parameterCount = args.GetCount();
	
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
	
	return Format("%s v%i.%i by %s", wndTitle, major, minor, author);
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