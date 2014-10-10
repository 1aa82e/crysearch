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

// Converts a CrySearch builtin type to a C++ type. Returns NULL if the type could not be converted.
const char* CodeGeneratorParseFieldType(const char* valueType)
{
	// Generate data type. (Based on a cheater's data type probability, the data types are sorted manually for human-like optimization.
	if (strcmp(valueType, "4 Bytes") == 0)
	{
		return "int";
	}
	else if (strcmp(valueType, "2 Bytes") == 0)
	{
		return "short";
	}
	else if (strcmp(valueType, "Float") == 0)
	{
		return "float";
	}
	if (strcmp(valueType, "Byte") == 0)
	{
		return "unsigned char";
	}
	else if (strcmp(valueType, "8 Bytes") == 0)
	{
		return "__int64";
	}
	else if (strcmp(valueType, "Double") == 0)
	{
		return "double";
	}
	else if (strcmp(valueType, "Array of Bytes") == 0)
	{
		return "unsigned char";
	}
	else if (strcmp(valueType, "String") == 0)
	{
		return "char";
	}
	else if (strcmp(valueType, "WString") == 0)
	{
		return "wchar_t";
	}
	else
	{
		return NULL;
	}
}

// Converts a string representation for a data type size.
// Returns the size in bytes of the type of data.
const int GetDataSizeFromValueType(const char* type)
{
	if (strcmp(type, "Byte") == 0)
	{
		return 1;
	}
	else if (strcmp(type, "2 Bytes") == 0)
	{
		return 2;
	}
	else if (strcmp(type, "4 Bytes") == 0)
	{
		return 4;
	}
	else if (strcmp(type, "8 Bytes") == 0)
	{
		return 8;
	}
	else if (strcmp(type, "Float") == 0)
	{
		return 4;
	}
	else if (strcmp(type, "Double") == 0)
	{
		return 8;
	}
	else if (strcmp(type, "String") == 0 || strcmp(type, "WString") == 0 || strcmp(type, "Array of Bytes") == 0)
	{
		return 1;
	}

	// Technically seen, this code path will never be reached. Tell the compiler to assume so.
	// Whenever the caller attempts to call this function with a parameter that is not listed in the conditional
	// listing, the behavior is undefined.
	__assume(0);
}

// Takes cheat table VariableType as input and outputs CrySearch ValueType.
const char* GetCrySearchValueTypeFromCheatTableVariableType(const char* varType, const BOOLEAN unicode)
{
	if (strcmp(varType, "Binary") == 0)
	{
		return "Byte";
	}
	else if (strcmp(varType, "Array of byte") == 0)
	{
		return "ArrayOfBytes";
	}
	else if (strcmp(varType, "String") == 0 && unicode)
	{
		return "WString";
	}
	else
	{
		// Return the default variable type for every other type because its the same.
		return varType;
	}
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