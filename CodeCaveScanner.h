#ifndef _CrySearch_CodeCaveScanner_h_
#define _CrySearch_CodeCaveScanner_h_

#include <Core/Core.h>

using namespace Upp;

#include "Disassembler.h"

// Represents a code cave type definition.
enum CodeCaveType
{
	// Initial value, no code cave found yet.
	UNKNOWN,
	
	// A collection of zero instructions (add byte ptr [eax], al).
	ZERO_INSTRUCTIONS,
	
	// A NOP sled (0x90).
	NOP_SLED,
	
	// An INT3 sled (INT3).
	INT3_SLED
};

// Represents the code cave scanner object.
class CodeCaveScanner
{
private:
	volatile bool mRunning;
	Thread mDisasmThread;

	void DoScanForCodeCaves(const SIZE_T base, const SIZE_T size, const int caveLength, const cs_mode arch);
	const CodeCaveType QualifyForStartOfCodeCave(const cs_insn* insn) const;
	
	typedef CodeCaveScanner CLASSNAME;
public:
	CodeCaveScanner();
	~CodeCaveScanner();
	
	const bool IsRunning() const;
	void Kill();
	void ScanForCodeCaves(const SIZE_T base, const SIZE_T size, const int caveLength);
	
	// Executed when the code cave scanner has started.
	Callback ScannerStarted;
	
	// Executed when the scanner found a result.
	Callback2<SIZE_T, int> ScannerResultFound;
	
	// Executed when the scanner has finished.
	Callback ScannerFinished;
};

#endif