#pragma once

#include <Windows.h>

// The following definitions identify the type of a handle that was enumerated in a process. They are used to 
// convert handle access flags into human readable string representations of the access flag combinations.
#define HANDLE_ACCESS_TYPE_FILE		0x1
#define HANDLE_ACCESS_TYPE_THREAD	0x2
#define HANDLE_ACCESS_TYPE_PROCESS	0x4
#define HANDLE_ACCESS_TYPE_REGKEY	0x8

// The following definitions are buffer size definitions that CrySearch uses to create safe-sized buffers. The
// buffers are created to hold the human readable string representations of handle access masks.
#define SAFE_BUFFER_SIZE_FILE		17
#define SAFE_BUFFER_SIZE_THREAD		12
#define SAFE_BUFFER_SIZE_PROCESS	13
#define SAFE_BUFFER_SIZE_REGKEY		11

// CrySearch uses data types to have the memory scanner identify certain data. The following type is used
// by CrySearch to pass a data type identifier through the program.
typedef int CCryDataType;

// The following definitions are CrySearch type definitions. They are passed as a 'CCryDataType' parameter
// through the program to identify memory data types. The values are indices of a drop list and may be used like so.
#define CRYDATATYPE_BYTE			0
#define CRYDATATYPE_2BYTES			1
#define CRYDATATYPE_4BYTES			2
#define CRYDATATYPE_8BYTES			3
#define CRYDATATYPE_FLOAT			4
#define CRYDATATYPE_DOUBLE			5
#define CRYDATATYPE_AOB				6
#define CRYDATATYPE_STRING			7
#define CRYDATATYPE_WSTRING			8

#ifdef __cplusplus
extern "C"
{
#endif

	// Sets 'bits' flags on the specified numeric value 'dw'.
	void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue);

	// Checks whether the integer value 'intVal' is a multiple the 'mulVal' value.
	const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal);

	// Parses an access mask value and returns the strings of the access constants it incoorporates.
	// The caller must specify a buffer and is responsible for its allocation and deletion. The recommended
	// size for the 'outBuffer' parameter depends on the type of handle. The size constants per type are defined above.
	void GetHandleObjectAccess(const DWORD type, const DWORD mask, char** const outBuffer, DWORD* const outSize);

	// Converts a CrySearch builtin type to a C++ type. Returns NULL if the type could not be converted.
	const char* CodeGeneratorParseFieldType(const CCryDataType valueType);

	// Takes cheat table VariableType as input and outputs CrySearch ValueType.
	const char* GetCrySearchValueTypeFromCheatTableVariableType(const char* varType, const BOOLEAN unicode);

	// Converts a string representation for a data type size. Returns the size in bytes of the type of data. Entering a value that is not
	// a valid data type as defined in the CrySearch headers may cause undefined behavior because the compiler assumes these values are not entered.
	const int GetDataSizeFromValueType(CCryDataType type);

	// Aligns an address in memory to the specific boundary.
	void AlignPointer(DWORD_PTR* Address, const DWORD Boundary);

	// Retrieves the string representation of a CrySearch data type. The return value is a pointer to a statically allocated string.
	// It returns NULL if the data type is not one of the definitions from the CrySearch headers.
	const char* GetCrySearchDataTypeRepresentation(const CCryDataType type);

	// Retrieves information about the operating system for a crash report. The recommended length for the 'maxLength' parameter is 256.
	void GetOSVersionString(char* const pOutString, const DWORD maxLength);

	// Tries to guess the data type of a value. The 'value' parameter must be a valid pointer to the data to guess.
	// Returns the guessed type or CRYDATATYPE_4BYTES if the type is 4 bytes or when the type could not be guessed.
	// This function is not yet implemented so it always returns 4-bytes.
	const CCryDataType GuessTypeOfValue(const void* value);

	// Retrieves information about the processor in the system. The first parameter should be a buffer of 128 bytes
	// that receives the processor information string. The string will contain information about supported machine
	// language extensions.
	void GetProcessorSupportInformation(char pProcInformationString[128]);

#ifdef __cplusplus
}
#endif