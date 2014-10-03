#ifndef _CrySearch_CodeGenerator_h_
#define _CrySearch_CodeGenerator_h_

#include <Core/Core.h>

using namespace Upp;

#include "GlobalDef.h"

// The codegenerator class. Construct using Factory function and destroy using CodeGenerator::Release.
class CodeGenerator
{
private:
	friend void CreateCodeGenerator(const AddressTable*, CodeGenerator**);
	
	struct __CodeUnits
	{
		DWORD Credits[40];
		DWORD Includes[7];
	} mCodeUnits;
	
	inline const char* GetCreditsCodeUnit() const		{ return (const char*)this->mCodeUnits.Credits; }
	inline const char* GetIncludesCodeUnit() const		{ return (const char*)this->mCodeUnits.Includes; }
	
	const AddressTable* mTable;
	bool external;
	
	String GenerateInternalEntry(const AddressTableEntry* entry, const int number);
	String GenerateExternalEntry(const AddressTableEntry* entry, const int number);
	
	void CreateConstants();
	
	CodeGenerator(const AddressTable* pTable);
public:
	~CodeGenerator();
	
	void SetExternal(bool external = true)	{ this->external = external; };
	
	void Generate(String& codenz);
	void Release() { delete this; };
};

void CreateCodeGenerator(const AddressTable* pTable, CodeGenerator** ppCodeGen);

#endif
