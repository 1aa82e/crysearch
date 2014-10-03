#ifndef _CrySearch_AsyncDisassembler_h_
#define _CrySearch_AsyncDisassembler_h_

#include "Disassembler.h"
#include "ProcessUtil.h"

const int GetPageIndexFromAddress(const SIZE_T address);
const MemoryRegion* GetPageFromAddress(const SIZE_T address);

// Single helper class that allows the user interface of CrySearch to disassemble pages in a thread-safe way.
class AsyncDisassembler
{
private:
	volatile bool mRunning;
	Thread mWorker;
	
	void DoDisassembly(const SIZE_T address);
	void RefreshDisasm(const SIZE_T addr, const SIZE_T size);
	void Disassemble(const SIZE_T address, const SIZE_T size, const ArchitectureDefinitions architecture, Vector<DisasmLine>& outInstructions);
	
	typedef AsyncDisassembler CLASSNAME;
public:
	AsyncDisassembler();
	~AsyncDisassembler();
	
	void Start(const SIZE_T address);
	void Kill();
	
	const bool IsRunning() const;
	
	Callback DisasmStarted;
	Callback1<SIZE_T> DisasmCompleted;
};

#endif