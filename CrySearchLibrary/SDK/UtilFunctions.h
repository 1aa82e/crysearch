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

	void CrySetBits(DWORD_PTR* const dw, const int lowBit, const int bits, const int newValue);
	const BOOL GetIsMultipleOf(const LONG_PTR intVal, const int mulVal);
	void GetHandleObjectAccess(const DWORD type, const DWORD mask, char** const outBuffer, DWORD* const outSize);
	const char* CodeGeneratorParseFieldType(const CCryDataType valueType);
	const char* GetCrySearchValueTypeFromCheatTableVariableType(const char* varType, const BOOLEAN unicode);
	const int GetDataSizeFromValueType(CCryDataType type);
	void AlignPointer(DWORD_PTR* Address, const DWORD Boundary);
	const char* GetCrySearchDataTypeRepresentation(const CCryDataType type);
	void GetOSVersionString(char* const pOutString, const DWORD maxLength);
	const CCryDataType GuessTypeOfValue(const void* value);

	// Retrieves information about the processor in the system. The first parameter should be a buffer of 128 bytes
	// that receives the processor information string. The string will contain information about supported machine
	// language extensions.
	void GetProcessorSupportInformation(char pProcInformationString[128]);

#ifdef __cplusplus
}
#endif