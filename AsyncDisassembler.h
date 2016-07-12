#ifndef _CrySearch_AsyncDisassembler_h_
#define _CrySearch_AsyncDisassembler_h_

#include "Disassembler.h"
#include "ProcessUtil.h"

const int GetPageIndexFromAddress(const SIZE_T address, SIZE_T* const sizePtr);
const DisasmMemoryRegion* GetPageFromAddress(const SIZE_T address);

// Represents worker-specific information during multi-threaded disassembly.
struct AsyncDisasmWorkerInformation : Moveable<AsyncDisasmWorkerInformation>
{
	// The base address of the part a worker has to disassemble.
	SIZE_T BaseAddress;
	
	// The size of the memory block a worker has to disassemble.
	SIZE_T MemorySize;
	
	// Holds the disassembled addresses for a specific worker.
	Vector<LONG_PTR> WorkerDisasmLines;
	
	// Indicates whether the worker has finished its work or not.
	bool HasFinished;
	
	// Let's create a default constructor to ease up the creation.
	AsyncDisasmWorkerInformation(const SIZE_T baseAddr, const SIZE_T memSize, const bool hasFinished)
	{
		this->BaseAddress = baseAddr;
		this->MemorySize = memSize;
		this->HasFinished = hasFinished;
	};
	
	// We also need to explicitly define a copy constructor for this construction to work.
	AsyncDisasmWorkerInformation(const AsyncDisasmWorkerInformation& copy)
	{
		this->BaseAddress = copy.BaseAddress;
		this->MemorySize = copy.MemorySize;
		this->HasFinished = copy.HasFinished;
		this->WorkerDisasmLines <<= copy.WorkerDisasmLines;
	};
};

// Single helper class that allows the user interface of CrySearch to disassemble pages in a thread-safe way.
class AsyncDisassembler
{
private:
	volatile bool mRunning;
	LONG_PTR mCurrentPageSize;
	SIZE_T mLastDisasmAddress;
	Vector<AsyncDisasmWorkerInformation> mWorkerInformations;
	
	void DoDisassembly(AsyncDisasmWorkerInformation* const pInformation);
	void Disassemble(const SIZE_T address, const SIZE_T size, const ArchitectureDefinitions architecture, Vector<LONG_PTR>& outInstructions);
	const bool PeekIsFinished() const;
	
	typedef AsyncDisassembler CLASSNAME;
public:
	AsyncDisassembler();
	~AsyncDisassembler();
	
	void Start(const SIZE_T address);
	void Kill();
	
	const bool PeekAndCopy(SIZE_T* const pAddress);
	const bool IsRunning() const;
	const LONG_PTR GetCurrentPageSize() const;
	
	// Executed when the disassembler has started.
	Callback DisasmStarted;
};

#endif