#include "../SDK/CrySearch.h"

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

// Retrieves information about the operating system for a crash report.
void GetOSVersionString(char* const pOutString, const DWORD maxLength)
{
	// Retrieve OS information.
	OSVERSIONINFOEX osv;
	SYSTEM_INFO sysInfo;
	const WORD lastPart = 0x0A0D;
	WORD major;
	WORD minor;
	char versionBuffer[8];

	// Copy the first part of the string into the output buffer.
	strcpy_s(pOutString, maxLength, "System Information:\r\n\r\nOS Version:\t\t\t");

	// Retrieve version of Windows.
	osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO*)&osv);

	// Parse version numbers into a version string for the crash report.
	if (osv.dwMajorVersion == 6)
	{
		if (osv.dwMinorVersion == 3)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				strcat_s(pOutString, maxLength, "Windows 8.1");
			}
			else
			{
				strcat_s(pOutString, maxLength, "Windows Server 2012 R2");
			}
		}
		else if (osv.dwMinorVersion == 2)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				strcat_s(pOutString, maxLength, "Windows 8");
			}
			else
			{
				strcat_s(pOutString, maxLength, "Windows Server 2012");
			}
		}
		else if (osv.dwMinorVersion == 1)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				strcat_s(pOutString, maxLength, "Windows 7");
			}
			else
			{
				strcat_s(pOutString, maxLength, "Windows Server 2008 R2");
			}
		}
		else if (osv.dwMinorVersion == 0)
		{
			if (osv.wProductType == VER_NT_WORKSTATION)
			{
				strcat_s(pOutString, maxLength, "Windows Vista");
			}
			else
			{
				strcat_s(pOutString, maxLength, "Windows Server 2008");
			}
		}
	}
	else if (osv.dwMajorVersion == 5)
	{
		if (osv.dwMinorVersion == 2)
		{
			if (GetSystemMetrics(SM_SERVERR2) == 0)
			{
				strcat_s(pOutString, maxLength, "Windows Server 2003");
			}
			else
			{
				strcat_s(pOutString, maxLength, "Windows Server 2003 R2");
			}
		}
		else if (osv.dwMinorVersion == 1)
		{
			strcat_s(pOutString, maxLength, "Windows XP");
		}
	}

	// Add the OS architecture to the crash report.
	GetNativeSystemInfo(&sysInfo);
	strcat_s(pOutString, maxLength, "\r\nArchitecture:\t\t");
	strcat_s(pOutString, maxLength, sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86" : "x64");

	// Add CrySearch architecture definition.
	strcat_s(pOutString, maxLength, "\r\nCrySearch:\t\t\t");
#ifdef _WIN64
	strcat_s(pOutString, maxLength, "x64 (");
#else
	strcat_s(pOutString, maxLength, "x86 (");
#endif
	
	// Retrieve the version number of CrySearch.
	CrySearchGetMajorMinorVersion(&major, &minor);
	_itoa_s(major, versionBuffer, sizeof(versionBuffer), 10);
	*(WORD*)&versionBuffer[strlen(versionBuffer)] = 0x2E;
	_itoa_s(minor, versionBuffer + strlen(versionBuffer), sizeof(versionBuffer) - strlen(versionBuffer), 10);
	*(WORD*)&versionBuffer[strlen(versionBuffer)] = 0x29;

	strcat_s(pOutString, maxLength, versionBuffer);
	strcat_s(pOutString, maxLength, (char*)&lastPart);
}

// Tries to guess the data type of a value. The 'value' parameter must be a valid pointer to the data to guess.
// Returns the guessed type or CRYDATATYPE_4BYTES if the type is 4 bytes or when the type could not be guessed.
const CCryDataType GuessTypeOfValue(const void* value)
{
	// The type could not be guessed. Return the default data type.
	return CRYDATATYPE_4BYTES;
}