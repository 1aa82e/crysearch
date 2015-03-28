#ifndef _CrySearch_CommandArgumentParser_h_
#define _CrySearch_CommandArgumentParser_h_

#include <Core/Core.h>

using namespace Upp;

// Class responsible for parsing CrySearch command line arguments.
class CommandArgumentParser
{
private:
	bool wasShellExec;
	bool showHelp;
	int parameterCount;
	DWORD procId;
	String filePath;
	
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
};

#endif