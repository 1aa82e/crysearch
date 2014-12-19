#ifndef _CrySearch_Disassembler_h_
#define _CrySearch_Disassembler_h_

#include <Core/Core.h>

using namespace Upp;

// Set BeaEngine to use __stdcall as default calling convention.
#define BEA_USE_STDCALL

#include "MemoryScanner.h"
#include "BeaEngine/include/BeaEngine.h"

// Dynamically link to disassembler library.
#ifdef _WIN64
	#pragma comment(lib, "BeaEngine/lib/BeaEngine64.lib")
#else
	#pragma comment(lib, "BeaEngine/lib/BeaEngine.lib")
#endif

#ifdef _cplusplus
extern "C"
{
#endif

int __stdcall CryDisasm(LPDISASM lpDisasm);

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

// Represents a line of disassembly in CrySearch, containing the following data:
// VirtualAddress:				The virtual address of the instruction set on the line;
// LengthInBytes:				The amount of bytes the instruction line contains;
// BytesStringRepresentation:	The string representation of a set of bytes, e.g. 00 CC AE;
// InstructionLine:				The disassembly string of the bytes, e.g. mov dword ptr[eax],ecx.
struct DisasmLine : Moveable<DisasmLine>
{
#ifdef _WIN64
	__int64 VirtualAddress;
#else
	int VirtualAddress;
#endif

	ArrayOfBytes BytesStringRepresentation;	
	String InstructionLine;
	
	// The virtual address should be set to 0 to be able to create checks against it.
	DisasmLine()
	{
		this->VirtualAddress = 0;
		this->BytesStringRepresentation.Data = NULL;
		this->BytesStringRepresentation.Size = 0;
	};
};

void RefreshExecutablePages(Vector<MemoryRegion>& pages);
DisasmLine DisasmGetLine(const SIZE_T address, ArchitectureDefinitions architecture);
DisasmLine DisasmGetPreviousLine(const SIZE_T address, ArchitectureDefinitions architecture);

#endif