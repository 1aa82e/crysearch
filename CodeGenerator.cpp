#include "CodeGenerator.h"
#include "UIUtilities.h"

#define GENERATED_HANDLEOPENING	"unsigned int pid;\r\n\tHANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);\r\n"
#define GENERATED_CLOSEHANDLE	"\tCloseHandle(proc);\r\n"
#define GENERATED_VOIDMAIN		"void main()\r\n{\r\n\t"
#define GENERATED_ENDVOIDMAIN	"}"
#define GENERATED_BYTESREAD		"\tDWORD bytesRead;\r\n\r\n"

// CodeGenerator class default constructor, which takes an address table to generate code from.
CodeGenerator::CodeGenerator()
{
	this->mTable = &loadedTable;
	this->external = false;
	this->CreateConstants();
}

// CodeGenerator class default destructor.
CodeGenerator::~CodeGenerator()
{
	
}

// Create credits inside generated code snippets.
void CodeGenerator::CreateConstants()
{
	// "/**\r\n"\
	// " * Code generated by CrySearch - Code Generator\r\n"\
	// " * by evolution536\r\n"\
	// " * www.unknowncheats.me\r\n"\
	// " * --------------------------------------------\r\n"\
	// " **/\r\n\r\n"
	this->mCodeUnits.Credits[0] = 0x0D2A2A2F;
	this->mCodeUnits.Credits[1] = 0x202A200A;
	this->mCodeUnits.Credits[2] = 0x65646F43;
	this->mCodeUnits.Credits[3] = 0x6E656720;
	this->mCodeUnits.Credits[4] = 0x74617265;
	this->mCodeUnits.Credits[5] = 0x62206465;
	this->mCodeUnits.Credits[6] = 0x72432079;
	this->mCodeUnits.Credits[7] = 0x61655379;
	this->mCodeUnits.Credits[8] = 0x20686372;
	this->mCodeUnits.Credits[9] = 0x6F43202D;
	this->mCodeUnits.Credits[10] = 0x47206564;
	this->mCodeUnits.Credits[11] = 0x72656E65;
	this->mCodeUnits.Credits[12] = 0x726F7461;
	this->mCodeUnits.Credits[13] = 0x2A200A0D;
	this->mCodeUnits.Credits[14] = 0x20796220;
	this->mCodeUnits.Credits[15] = 0x6C6F7665;
	this->mCodeUnits.Credits[16] = 0x6F697475;
	this->mCodeUnits.Credits[17] = 0x3633356E;
	this->mCodeUnits.Credits[18] = 0x2A200A0D;
	this->mCodeUnits.Credits[19] = 0x77777720;
	this->mCodeUnits.Credits[20] = 0x6B6E752E;
	this->mCodeUnits.Credits[21] = 0x6E776F6E;
	this->mCodeUnits.Credits[22] = 0x61656863;
	this->mCodeUnits.Credits[23] = 0x6D2E7374;
	this->mCodeUnits.Credits[24] = 0x200A0D65;
	this->mCodeUnits.Credits[25] = 0x2D2D202A;
	this->mCodeUnits.Credits[26] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[27] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[28] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[29] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[30] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[31] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[32] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[33] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[34] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[35] = 0x2D2D2D2D;
	this->mCodeUnits.Credits[36] = 0x0A0D2D2D;
	this->mCodeUnits.Credits[37] = 0x2F2A2A20;
	this->mCodeUnits.Credits[38] = 0x0A0D0A0D;
	this->mCodeUnits.Credits[39] = 0x00000000;
	
	// "#include <windows.h>\r\n\r\n"
	this->mCodeUnits.Includes[0] = 0x636E6923;
	this->mCodeUnits.Includes[1] = 0x6564756C;
	this->mCodeUnits.Includes[2] = 0x69773C20;
	this->mCodeUnits.Includes[3] = 0x776F646E;
	this->mCodeUnits.Includes[4] = 0x3E682E73;
	this->mCodeUnits.Includes[5] = 0x0A0D0A0D;
	this->mCodeUnits.Includes[6] = 0x00000000;
}

// Generates a programming language expression from an entry in the address table.
String CodeGenerator::GenerateInternalEntry(const AddressTableEntry* const entry, const int number)
{
	String taskOutput;

	// Parse field type to language version.
	String fieldType = CodeGeneratorParseFieldType(entry->ValueType);
	String description = entry->Description;
	
	// If the description contains spaces, those must be removed and replaced by underscores.
	if (!description.IsEmpty())
	{
		description.Replace(" ", "_");
	}
	
	// Create field and append to output result.
	if (entry->IsRelative == TRUE)
	{
		const SIZE_T modBase = mModuleManager->GetModuleFromContainedAddress(entry->Address)->BaseAddress;
		const String modName = mModuleManager->GetModuleFilename(modBase);
		taskOutput += Format("%s* %s = (%s*)GetModuleHandle(\"%s\") + 0x%llX;\r\n", fieldType, description.IsEmpty() ? Format("__unknown%i", number)
			: description, fieldType, modName, (__int64)(entry->Address - modBase));
	}
	else
	{
		taskOutput += Format("%s* %s = (%s*)0x%llX;\r\n", fieldType, description.IsEmpty() ? Format("__unknown%i", number)
			: description, fieldType, entry->Address);
	}

	return taskOutput;
}

// Generates a programming language expression from an address table entry.
// This function assembles the expression from external memory access view.
String CodeGenerator::GenerateExternalEntry(const AddressTableEntry* const entry, const int number)
{
	String taskOutput;
	
	// Parse field type to language version.
	String fieldType = CodeGeneratorParseFieldType(entry->ValueType);
	String description = entry->Description.IsEmpty() ? Format("__unknown%i", number) : entry->Description;
	String size = "sizeof(fieldType)";
	
	// If the description contains spaces, those must be removed and replaced by underscores.
	description.Replace(" ", "_");
	
	// Create value data field, readprocessmemory and writeprocessmemory calls. The user may choose which he wants himself.
	if (entry->ValueType == CRYDATATYPE_STRING || entry->ValueType == CRYDATATYPE_AOB)
	{
		taskOutput += Format("\t%s %s[%i];\r\n", fieldType, description, entry->Size);
		size = FormatIntSpecial(entry->Size);
	}
	else
	{
		taskOutput += Format("\t%s %s;\r\n", fieldType, description);
	}
	
	if (entry->IsRelative == TRUE)
	{
		taskOutput += Format("\tconst SIZE_T %s_Base = (SIZE_T)GetModuleHandle(\"%s\");\r\n", description, entry->ModuleName);
		taskOutput += Format("\tReadProcessMemory(proc, (void*)(%s_Base + 0x%llX), &%s, %s, &bytesRead);\r\n"
			, description, (__int64)(entry->Address - mModuleManager->FindModule(entry->ModuleName)->BaseAddress), description, size);
		
		taskOutput += Format("\tWriteProcessMemory(proc, (void*)(%s_Base + 0x%llX), &%s, %s, &bytesRead);\r\n\r\n"
			, description, (__int64)(entry->Address - mModuleManager->FindModule(entry->ModuleName)->BaseAddress), description, size);
	}
	else
	{
		taskOutput += Format("\tReadProcessMemory(proc, (void*)0x%llX, &%s, %s, &bytesRead);\r\n"
			, entry->Address, description, size);
		
		taskOutput += Format("\tWriteProcessMemory(proc, (void*)0x%llX, &%s, %s, &bytesRead);\r\n\r\n"
			, entry->Address, description, size);
	}
	
	return taskOutput;
}

// Generates a code snippet from the entire inputted address table.
void CodeGenerator::Generate(String& codenz)
{
	codenz = this->GetCreditsCodeUnit();
		
	if (this->external)
	{
		codenz += this->GetIncludesCodeUnit();
		codenz += GENERATED_VOIDMAIN;
		codenz += GENERATED_HANDLEOPENING;
		codenz += GENERATED_BYTESREAD;
		
		const int count = this->mTable->GetCount();
		for (int i = 0; i < count; ++i)
		{
			codenz += this->GenerateExternalEntry((*this->mTable)[i], i);
		}
		
		codenz += GENERATED_CLOSEHANDLE;
		codenz += GENERATED_ENDVOIDMAIN;
	}
	else
	{
		const int count = this->mTable->GetCount();
		for (int i = 0; i < count; ++i)
		{
			codenz += this->GenerateInternalEntry((*this->mTable)[i], i);
		}
	}
}