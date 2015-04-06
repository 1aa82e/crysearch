#ifndef _CrySearch_CommandArgumentParser_h_
#define _CrySearch_CommandArgumentParser_h_

#include <Core/Core.h>

using namespace Upp;

#define CRYSEARCH_COMMAND_OPTION_PE			0x1
#define CRYSEARCH_COMMAND_OPTION_IMPORTS	0x2
#define CRYSEARCH_COMMAND_OPTION_THREADS	0x4
#define CRYSEARCH_COMMAND_OPTION_MODULES	0x8

// Class responsible for parsing CrySearch command line arguments.
class CommandArgumentParser
{
private:
	bool wasShellExec;
	bool showHelp;
	int parameterCount;
	DWORD procId;
	String filePath;
	DWORD options;
	String outputFile;
	
	void Parse(const Vector<String>& args);
public:
	CommandArgumentParser(const Vector<String>& args);
	~CommandArgumentParser();
	
	const int GetParameterCount() const;
	String GetHelpOutput() const;
	const bool GetWasShellExecuted() const;
	const bool WasHelpCommandFound() const;
	const DWORD GetProcessId() const;
	const String& GetFilePath() const;
	const DWORD GetOptions() const;
	const String& GetOutputFile() const;
};

#endif