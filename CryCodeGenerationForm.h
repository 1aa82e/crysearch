#ifndef _CrySearch_CryCodeGenerationForm_h_
#define _CrySearch_CryCodeGenerationForm_h_

#include <CtrlLib/CtrlLib.h>

#include "CodeGenerator.h"

using namespace Upp;

// When the address table contains addresses and a process is opened, C++ code can be generated
// from this window, using the contents of the address table.
class CryCodeGenerationForm : public TopWindow
{
private:
	Button mGenerate;
	Button mClose;
	LineEdit mCodeField;
	Label mLanguageSelectorLabel;
	DropList mLanguageSelector;
	Option mCreateExternalCode;
	
	CodeGenerator* mCodeGen;
	
	void CloseForm();
	void GenerateButtonClicked();
	
	typedef CryCodeGenerationForm CLASSNAME;
public:
	CryCodeGenerationForm();
	~CryCodeGenerationForm();
};

#endif
