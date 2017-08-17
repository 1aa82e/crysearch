#include "../SDK/CrySearch.h"

// Sets 'bits' flags on the specified numeric value 'dw'.
void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue)
{
	const DWORD_PTR mask = (1 << bits) - 1;
	*dw = (*dw & ~(mask << lowBit)) | (newValue << lowBit);
}

// Checks whether the integer value 'intVal' is a multiple the 'mulVal' value.
const bool GetIsMultipleOf(const LONG_PTR intVal, const int mulVal)
{
	return (intVal % mulVal) == 0;
}

// Converts a CrySearch builtin type to a C++ type. Returns NULL if the type could not be converted.
const char* CodeGeneratorParseFieldType(const CCryDataType valueType)
{
	// Generate data type. (Based on a cheater's data type probability, the data types are sorted manually for human-like optimization.
	switch (valueType)
	{
		case CRYDATATYPE_BYTE:
		case CRYDATATYPE_AOB:
			return "unsigned char";
		case CRYDATATYPE_2BYTES:
			return "short";
		case CRYDATATYPE_4BYTES:
			return "int";
		case CRYDATATYPE_8BYTES:
			return "__int64";
		case CRYDATATYPE_FLOAT:
			return "float";
		case CRYDATATYPE_DOUBLE:
			return "double";
		case CRYDATATYPE_STRING:
			return "char";
		case CRYDATATYPE_WSTRING:
			return "wchar_t";
		default:
			return NULL;
	}
}

// Converts a string representation for a data type size. Returns the size in bytes of the type of data. Entering a value that is not
// a valid data type as defined in the CrySearch headers may cause undefined behavior because the compiler assumes these values are not entered.
const int GetDataSizeFromValueType(CCryDataType type)
{
	switch (type)
	{
	case CRYDATATYPE_BYTE:
		return 1;
	case CRYDATATYPE_2BYTES:
		return 2;
	case CRYDATATYPE_4BYTES:
		return 4;
	case CRYDATATYPE_8BYTES:
		return 8;
	case CRYDATATYPE_FLOAT:
		return 4;
	case CRYDATATYPE_DOUBLE:
		return 8;
	case CRYDATATYPE_STRING:
	case CRYDATATYPE_WSTRING:
	case CRYDATATYPE_AOB:
		return 1;
	default:
		return 0;
	}
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

// Retrieves the string representation of a CrySearch data type. The return value is a pointer to a statically allocated string.
// It returns NULL if the data type is not one of the definitions from the CrySearch headers.
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
		case CRYDATATYPE_STRING:
			return "String";
		case CRYDATATYPE_WSTRING:
			return "WString";
		case CRYDATATYPE_AOB:
			return "Array of Bytes";
		default:
			return NULL;
	}
}

// Retrieves information about the operating system for a crash report. The recommended length for the 'maxLength' parameter is 256.
void GetOSVersionString(char* const pOutString, const DWORD maxLength)
{
	// Retrieve OS information.
	OSVERSIONINFOEX osv;
	SYSTEM_INFO sysInfo;
	const WORD lastPart = 0x0A0D;
	WORD major;
	WORD minor;
	char versionBuffer[8];

	// GetVersionEx alternative on ntdll.dll level.
	typedef NTSTATUS(__stdcall* RtlGetVersionPrototype)(POSVERSIONINFOEX osVersion);
	RtlGetVersionPrototype RtlGetVersion = (RtlGetVersionPrototype)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	
	// Copy the first part of the string into the output buffer.
	strcpy_s(pOutString, maxLength, "System Information:\r\n\r\nOS Version:\t\t\t");

	// Retrieve version of Windows.
	osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	RtlGetVersion(&osv);

	// Parse version numbers into a version string for the crash report.
	if (osv.dwMajorVersion == 10)
	{
		strcat_s(pOutString, maxLength, "Windows 10");
	}
	else if (osv.dwMajorVersion == 6)
	{
		if (osv.dwMinorVersion == 4)
		{
			strcat_s(pOutString, maxLength, "Windows 10");
		}
		else if (osv.dwMinorVersion == 3)
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
	else
	{
		strcat_s(pOutString, maxLength, "Unknown Windows version");
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

// Tries to guess the data type of a value according to the parameter structure.
const CCryDataType GuessTypeOfValue(PTYPE_GUESS_PARAMS const pParams)
{
	// First interpret it as an integer to see whether it has some human-readable integer value.
	if (pParams->MaxSize >= sizeof(int) && ((*(int*)pParams->Value >= -100000 && *(int*)pParams->Value <= 100000) || (*(int*)pParams->Value % 100 == 0)))
	{
		// Guessed to be of integer data type.
		pParams->OutDataLength = 0;
		return CRYDATATYPE_4BYTES;
	}
	
	// Check whether the first four characters are in the range of ASCII characters.
	if (pParams->MaxSize >= 4 * sizeof(char))
	{
		bool res = true;
		unsigned int i = 0;
		for (; i < 4 && res; ++i)
		{
			if (((char*)pParams->Value)[i] < 0x20 || ((char*)pParams->Value)[i] > 0x7E)
			{
				res = false;
			}
		}

		// Guessed to be of type ASCII string, currently of 4 bytes in length.
		if (res)
		{
			// See whether the string is longer, up to a certain threshold (32).
			for (; i < min(32, pParams->MaxSize) && ((char*)pParams->Value)[i] != 0; ++i);
			pParams->OutDataLength = i;
			return CRYDATATYPE_STRING;
		}
	}

	// Check whether the value could be a pointer.
	if (pParams->MaxSize >= pParams->PointerSize)
	{
		pParams->OutDataLength = 0;

		// 32-bit or 64-bit architecture?
		if (pParams->PointerSize == sizeof(int))
		{
			if (*(unsigned int*)pParams->Value >= pParams->AddressLowerBound && *(unsigned int*)pParams->Value <= pParams->AddressUpperBound)
			{
				return CRYDATATYPE_4BYTES;
			}
		}
		else
		{
			if (*(unsigned __int64*)pParams->Value >= pParams->AddressLowerBound && *(unsigned __int64*)pParams->Value <= pParams->AddressUpperBound)
			{
				return CRYDATATYPE_8BYTES;
			}
		}
	}

	// Now we see if it matches the human-readable condition while interpreted as float.
	if (pParams->MaxSize >= sizeof(float) && (*(float*)pParams->Value >= -100000.0f && *(float*)pParams->Value <= 100000.0f))
	{
		// Guessed to be of float data type.
		pParams->OutDataLength = 0;
		return CRYDATATYPE_FLOAT;
	}
	
	// The same if it matches the human-readable condition while interpreted as double.
	if (pParams->MaxSize >= sizeof(double) && (*(double*)pParams->Value >= -100000.0 && *(double*)pParams->Value <= 100000.0))
	{
		// Guessed to be of float data type.
		pParams->OutDataLength = 0;
		return CRYDATATYPE_DOUBLE;
	}

	// The type could not be guessed. Return the default data type.
	pParams->OutDataLength = 0;
	return CRYDATATYPE_4BYTES;
}

// Retrieves drive letter that is mapped to a native device name, retrieved by handle information. Returns the resolved drive letter
// in ASCII character code if succeeded and 0 if failed.
const char GetMappedDriveLetter(const char* mappedDrive, const unsigned int length)
{
	// Prepare string representation buffer, where per iteration only the first character will change.
	char query[4];
	query[1] = ':';
	query[2] = 0;

	// ASCII codes 65 until 90 are capital A-Z, which represent drive letters.
	for (char i = 65; i <= 90; ++i)
	{
		// Create a string representation for the current character.
		query[0] = i;

		// Query the device name.
		char targetPath[MAX_PATH];
		DWORD numChars = QueryDosDeviceA(query, targetPath, MAX_PATH);
		
		// Did the query succeed and does it match our request?
		if (numChars && strstr(mappedDrive, targetPath))
		{
			return i;
		}
	}

	// Nothing was found!
	return 0;
}