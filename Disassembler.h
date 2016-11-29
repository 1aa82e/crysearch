#ifndef _CrySearch_Disassembler_h_
#define _CrySearch_Disassembler_h_

#include <Core/Core.h>

using namespace Upp;

// Set BeaEngine to use __stdcall as default calling convention.
#define BEA_USE_STDCALL

#include "MemoryScanner.h"

// Using the old version of BeaEngine or the new v5 one (dev)?
//#define BEA_USE_V4

#ifdef BEA_USE_V4
	#include "BeaEngine/BeaEngine v4/include/BeaEngine.h"
#else
	#include "BeaEngine/BeaEngine v5/include/BeaEngine.h"
#endif

// Dynamically link to disassembler library.
#ifdef _WIN64
	#ifdef BEA_USE_V4
		#pragma comment(lib, "BeaEngine/BeaEngine v4/lib/BeaEngine64.lib")
	#else
		#pragma comment(lib, "BeaEngine/BeaEngine v5/lib/BeaEngine64.lib")
	#endif
#else
	#ifdef BEA_USE_V4
		#pragma comment(lib, "BeaEngine/BeaEngine v4/lib/BeaEngine.lib")
	#else
		#pragma comment(lib, "BeaEngine/BeaEngine v5/lib/BeaEngine.lib")
	#endif
#endif

#ifdef _cplusplus
extern "C"
{
#endif

const int __stdcall CryDisasm(LPDISASM lpDisasm);

#ifdef _cplusplus
}
#endif

#ifdef _WIN64
	#define ASM_LINE_MAX_BYTES 19
#else
	#define ASM_LINE_MAX_BYTES 15
#endif

// Architecture definitions
enum ArchitectureDefinitions
{
	ARCH_X86 = 0,
	ARCH_X64 = 64
};

// Represents a memory region solely for disassembler use.
struct DisasmMemoryRegion : Moveable<DisasmMemoryRegion>
{
	// The base address of a block of memory.
	SIZE_T BaseAddress;
	
	// The size of a block of memory.
	SIZE_T MemorySize;
};

// Refreshes the pages that may contain code to be disassembled.
void RefreshExecutablePages(Vector<DisasmMemoryRegion>& pages);

// Retrieves an instruction that precedes that one at the specified address.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves an instruction at the specified address.
String DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves only the instruction bytes at the specified address.
void DisasmForBytes(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob, Vector<char>* const optOutMasking);

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

#endif