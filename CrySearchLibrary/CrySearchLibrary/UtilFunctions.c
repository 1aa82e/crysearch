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
const char* CodeGeneratorParseFieldType(const CCryDataType valueType)
{
	// Generate data type. (Based on a cheater's data type probability, the data types are sorted manually for human-like optimization.
	if (valueType == CRYDATATYPE_4BYTES)
	{
		return "int";
	}
	else if (valueType == CRYDATATYPE_2BYTES)
	{
		return "short";
	}
	else if (valueType == CRYDATATYPE_FLOAT)
	{
		return "float";
	}
	if (valueType == CRYDATATYPE_BYTE)
	{
		return "unsigned char";
	}
	else if (valueType == CRYDATATYPE_8BYTES)
	{
		return "__int64";
	}
	else if (valueType == CRYDATATYPE_DOUBLE)
	{
		return "double";
	}
	else if (valueType == CRYDATATYPE_AOB)
	{
		return "unsigned char";
	}
	else if (valueType == CRYDATATYPE_STRING)
	{
		return "char";
	}
	else if (valueType == CRYDATATYPE_WSTRING)
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
const int GetDataSizeFromValueType(CCryDataType type)
{
	if (type == CRYDATATYPE_BYTE)
	{
		return 1;
	}
	else if (type == CRYDATATYPE_2BYTES)
	{
		return 2;
	}
	else if (type == CRYDATATYPE_4BYTES)
	{
		return 4;
	}
	else if (type == CRYDATATYPE_8BYTES)
	{
		return 8;
	}
	else if (type == CRYDATATYPE_FLOAT)
	{
		return 4;
	}
	else if (type == CRYDATATYPE_DOUBLE)
	{
		return 8;
	}
	else if (type == CRYDATATYPE_AOB || type == CRYDATATYPE_STRING || type == CRYDATATYPE_WSTRING)
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

// Retrieves the string representation of a CrySearch data type.
const char* GetCrySearchDataTypeRepresentation(const CCryDataType type)
{
	switch (type)
	{
		case CRYDATATYPE_BYTE:
			return "Byte";
		case CRYDATATYPE_2BYTES:
			return "2 Bytes";
		case CRYDATATYPE_4BYTES:
			return "4 Bytes";
		case CRYDATATYPE_8BYTES:
			return "8 Bytes";
		case CRYDATATYPE_FLOAT:
			return "Float";
		case CRYDATATYPE_DOUBLE:
			return "Double";
		case CRYDATATYPE_AOB:
			return "Array of Bytes";
		case CRYDATATYPE_STRING:
			return "String";
		case CRYDATATYPE_WSTRING:
			return "WString";
	}

	// The data type could not be resolved.
	return NULL;
}