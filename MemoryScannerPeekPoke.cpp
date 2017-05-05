#include "MemoryScanner.h"
#include "BackendGlobalDef.h"

// ---------------------------------------------------------------------------------------------

// Writes the input data with its specified size to the specified address.
void MemoryScanner::Poke(const SIZE_T address, const void* value, const unsigned int size) const
{
	if (value)
	{
		CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value, size, NULL);
	}
}

// Writes a byte array with specified size to the specified address.
void MemoryScanner::PokeB(const SIZE_T address, const ArrayOfBytes& value) const
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value.Data, value.Size, NULL);
}

// Writes an ANSI string with specified size to the specified address.
void MemoryScanner::PokeA(const SIZE_T address, const String& value) const
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value.Begin(), value.GetLength(), NULL);
}

// Writes a unicode string with specified size to the specified address.
void MemoryScanner::PokeW(const SIZE_T address, const WString& value) const
{
	CrySearchRoutines.CryWriteMemoryRoutine(this->mOpenedProcessHandle, (void*)address, value.Begin(), value.GetLength() * sizeof(wchar), NULL);
}

// ---------------------------------------------------------------------------------------------

// Reads a value with specified size from a memory address into the specified outBuffer.
const bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, void* const outBuffer) const
{
	SIZE_T bytesRead;
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, outBuffer, size, &bytesRead);
	return bytesRead == size;
}

// Reads a byte array with specified size from a memory address into the specified outBuffer.
const bool MemoryScanner::PeekB(const SIZE_T address, const unsigned int size, ArrayOfBytes& outBuffer) const
{
	outBuffer.Allocate(size);
	SIZE_T bytesRead;
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, outBuffer.Data, size, &bytesRead);
	return bytesRead == size;
}

// Reads a unicode string with specified size from the specified address.
const bool MemoryScanner::PeekW(const SIZE_T address, const unsigned int size, WString& outBuffer) const
{
	const unsigned int bytesSize = size * sizeof(wchar);
	SIZE_T bytesRead;
	WStringBuffer buffer(size);
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, buffer.Begin(), bytesSize, &bytesRead);
	buffer.Strlen();
	outBuffer = buffer;
	return bytesRead == bytesSize;
}

// Reads an ANSI string with specified size from the specified address.
const bool MemoryScanner::PeekA(const SIZE_T address, const unsigned int size, String& outBuffer) const
{
	SIZE_T bytesRead;
	StringBuffer buffer(size);
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, buffer.Begin(), size, &bytesRead);
	buffer.Strlen();
	outBuffer = buffer;
	return bytesRead == size;
}