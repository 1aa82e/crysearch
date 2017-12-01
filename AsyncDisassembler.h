#ifndef _CrySearch_AsyncDisassembler_h_
#define _CrySearch_AsyncDisassembler_h_

#include "Disassembler.h"
#include "ProcessUtil.h"

// Single helper class that allows the user interface of CrySearch to disassemble pages in a thread-safe way.
class AsyncDisassembler
{
private:
	volatile bool mRunning;
	LONG_PTR mCurrentPageSize;
	SIZE_T mLastDisasmAddress;
	Thread mDisasmThread;
	
	void Disassemble(const SIZE_T address, const SIZE_T size, const cs_mode architecture);
	
	typedef AsyncDisassembler CLASSNAME;
public:
	AsyncDisassembler();
	~AsyncDisassembler();
	
	void Start(const SIZE_T address, const MemoryRegion& curRegion);
	void Kill();
	
	const bool PeekIsFinished(SIZE_T* const pAddress);
	const bool IsRunning() const;
	const LONG_PTR GetCurrentPageSize() const;
	
	// Executed when the disassembler has started.
	Callback DisasmStarted;
};

#endif