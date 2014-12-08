#pragma once

#include <Windows.h>

// Conversion type definitions for GetHandleObjectAccess.
#define HANDLE_ACCESS_TYPE_FILE		0x1
#define HANDLE_ACCESS_TYPE_THREAD	0x2
#define HANDLE_ACCESS_TYPE_PROCESS	0x4
#define HANDLE_ACCESS_TYPE_REGKEY	0x8

// Safe buffer size definitions for GetHandleObjectAccess.
#define SAFE_BUFFER_SIZE_FILE		17
#define SAFE_BUFFER_SIZE_THREAD		12
#define SAFE_BUFFER_SIZE_PROCESS	13
#define SAFE_BUFFER_SIZE_REGKEY		11

// Defines a CrySearch data type representation.
typedef int CCryDataType;

// Possible CrySearch data types. Droplist indices can be used to identify.
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

	// Retrieves information about the processor in the current system.
	// Returns a string of supported extensions into the first parameter.
	void GetProcessorSupportInformation(char pProcInformationString[128]);

#ifdef __cplusplus
}
#endif