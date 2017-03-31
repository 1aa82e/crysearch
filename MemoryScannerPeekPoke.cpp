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

// Reads T value with sizeof(T) size from the specified address.
template <typename T>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, T* outBuffer) const
{
	SIZE_T bytesRead;
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, outBuffer, sizeof(T), &bytesRead);
	return bytesRead == sizeof(T);
}

// Reads a byte array with specified size from the specified address.
template <>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, ArrayOfBytes* outBuffer) const
{
	outBuffer->Allocate(size);
	SIZE_T bytesRead;
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, outBuffer->Data, size, &bytesRead);
	return bytesRead == size;
}

// Reads a unicode string with specified size from the specified address.
template <>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, WString* outBuffer) const
{
	const unsigned int bytesSize = size * sizeof(wchar);
	SIZE_T bytesRead;
	WStringBuffer buffer(size);
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, buffer.Begin(), bytesSize, &bytesRead);
	buffer.Strlen();
	*outBuffer = buffer;
	return bytesRead == bytesSize;
}

// Reads an ANSI string with specified size from the specified address.
template <>
bool MemoryScanner::Peek(const SIZE_T address, const unsigned int size, String* outBuffer) const
{
	SIZE_T bytesRead;
	StringBuffer buffer(size);
	CrySearchRoutines.CryReadMemoryRoutine(this->mOpenedProcessHandle, (void*)address, buffer.Begin(), size, &bytesRead);
	buffer.Strlen();
	*outBuffer = buffer;
	return bytesRead == size;
}

// ---------------------------------------------------------------------------------------------

// template implementations for linkage errors.
template bool MemoryScanner::Peek<Byte>(const SIZE_T address, const unsigned int size, Byte* outBuffer) const;
template bool MemoryScanner::Peek<short>(const SIZE_T address, const unsigned int size, short* outBuffer) const;
template bool MemoryScanner::Peek<int>(const SIZE_T address, const unsigned int size, int* outBuffer) const;
template bool MemoryScanner::Peek<__int64>(const SIZE_T address, const unsigned int size, __int64* outBuffer) const;
template bool MemoryScanner::Peek<float>(const SIZE_T address, const unsigned int size, float* outBuffer) const;
template bool MemoryScanner::Peek<double>(const SIZE_T address, const unsigned int size, double* outBuffer) const;