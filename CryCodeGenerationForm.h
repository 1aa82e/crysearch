#ifndef _CrySearch_CryCodeGenerationForm_h_
#define _CrySearch_CryCodeGenerationForm_h_

#include <CtrlLib/CtrlLib.h>
#include <CodeEditor/CodeEditor.h>

#include "CodeGenerator.h"

using namespace Upp;

class CryCodeGenerationForm sealed : public TopWindow
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
	//void ExternalCheckChanged();
	//void LanguageSelectionChanged();
	void GenerateButtonClicked();
	
	typedef CryCodeGenerationForm CLASSNAME;
public:
	CryCodeGenerationForm();
	~CryCodeGenerationForm();
};

#endif
