#ifndef _CrySearch_Disassembler_h_
#define _CrySearch_Disassembler_h_

#include <Core/Core.h>

using namespace Upp;

// Set BeaEngine to use __stdcall as default calling convention.
#define BEA_USE_STDCALL

#include "MemoryScanner.h"

// Using the old version of BeaEngine or the new v5 one (dev)?
#ifdef _WIN64
	#define BEA_USE_V4
#endif

// Are we using the conventional (unfortunately detected as malware by Windows Defender) version of BeaEngine or the new one?
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

// C++ wrapper around the Disasm function, which is written in C.
const int __stdcall CryDisasm(LPDISASM lpDisasm);

#ifdef _cplusplus
}
#endif

// Specifies the maximum length of an instruction in both x86 and x64.
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

// Refreshes the pages that may contain code to be disassembled.
void RefreshExecutablePages(Vector<MemoryRegion>& pages);

// Retrieves an instruction that precedes that one at the specified address.
const SIZE_T DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves an instruction at the specified address.
String DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

// Retrieves only the instruction bytes at the specified address.
void DisasmForBytes(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob, Vector<char>* const optOutMasking);

// Retrieves an instruction at the specified address, also resolving intermodular calls.
String DisasmGetLineEx(const SIZE_T address, ArchitectureDefinitions architecture, ArrayOfBytes* const outAob);

#endif