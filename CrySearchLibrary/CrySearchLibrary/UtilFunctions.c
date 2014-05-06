#include "../SDK/UtilFunctions.h"

// Sets bit flags on a specified numeric value.
void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue)
{
	const DWORD_PTR mask = (1 << bits) - 1;
	*dw = (*dw & ~(mask << lowBit)) | (newValue << lowBit);
}

// Checks whether an integer value is a multiple of another value.
const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal)
{
	return (intVal % mulVal) == 0;
}

#ifdef _WIN64
	// Aligns an address in memory to the specific boundary.
	void AlignPointer(DWORD_PTR* Address, const DWORD Boundary)
	{
		if (Boundary > 0)
		{
			if ((*Address % Boundary) > 0)
			{
				const DWORD_PTR tmp = *Address;
				*Address = (tmp + Boundary) - (tmp % Boundary);
			}
		}
	}
#endif