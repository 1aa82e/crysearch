#ifndef _CrySearch_PointerScanner_h_
#define _CrySearch_PointerScanner_h_

#include <Core/Core.h>

using namespace Upp;

#include "BackendGlobalDef.h"

// Represents a pointer scan result.
struct PointerScanResult : public Moveable<PointerScanResult>
{
	// The base address of the pointer.
	SIZE_T BaseAddress;
	
	// The offsets associated with the pointer.
	Vector<SIZE_T> PointerOffsets;
};

// Storage for the pointer scan results.
extern Vector<PointerScanResult> PointerScanResults;

// The pointer scanner class. It disassembles all instructions in the process memory, takes out
// the addresses it finds, and finds static addresses for dynamically allocated values.
class PointerScanner
{
private:
	typedef PointerScanner CLASSNAME;
	CoWork dispar;
	SIZE_T maxoffset;
	SIZE_T maxrec;
	volatile bool killSwitch;
	int readSize;
	CriticalSection mScanResultsCS;
	volatile int completionCount;
	CriticalSection mCompletionCS;
	
	void AddPointerScanResult(const SIZE_T base, const Vector<SIZE_T>& offsets);
	void ProcessMemoryPage(const MemoryRegion& reg, const SIZE_T pAddress);
	const bool ScanStaticAddress(const SIZE_T staticAddr, const SIZE_T pAddress, unsigned int* pRecursionLevel, Vector<SIZE_T>& pOffsets) const;
public:
	PointerScanner();
	~PointerScanner() noexcept(true);
	
	void StartPointerScan(const SIZE_T pAddress, const SIZE_T pMaxOff, const SIZE_T pMaxRec);
	const bool PollPointerScanCompleted() const;
	void Kill();
};

#endif