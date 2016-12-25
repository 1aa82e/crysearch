#include "CryCodeGenerationForm.h"
#include "ImlProvider.h"

// The CryCodeGenerationForm default constructor.
CryCodeGenerationForm::CryCodeGenerationForm()
{
	this->Title("Generate Code").Icon(CrySearchIml::CodeGenerationButton()).Sizeable().SetRect(0, 0, 550, 400);
	
	this->mGenerate <<= THISBACK(GenerateButtonClicked);
	this->mClose <<= THISBACK(CloseForm);
	
	//this->mCreateExternalCode.WhenAction = THISBACK(ExternalCheckChanged);
	
	*this
		<< this->mLanguageSelectorLabel.SetLabel("Language:").LeftPos(5, 100).TopPos(5, 25)
		<< this->mLanguageSelector.Add("C++").LeftPos(80, 100).TopPos(5, 25)
		<< this->mCreateExternalCode.SetLabel("Generate external code (Win32 API's)").HSizePos(5, 5).TopPos(30, 25)
		<< this->mCodeField.HSizePos(5, 5).VSizePos(90, 35)
		<< this->mGenerate.SetLabel("Generate").RightPos(5, 80).TopPos(60, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 70).BottomPos(5, 25)
	;

	this->mLanguageSelector.SetIndex(0);
	
	// Create code generator instance in the scope of the window.
	this->mCodeGen = new CodeGenerator();
}

// The CryCodeGenerationForm default destructor.
CryCodeGenerationForm::~CryCodeGenerationForm()
{
	delete this->mCodeGen;
}

// Generates code from the underlying address table.
void CryCodeGenerationForm::GenerateButtonClicked()
{
	// Set internal/external switch for code generation.
	this->mCodeGen->SetExternal(this->mCreateExternalCode);
	
	// Generate code.
	String codenz;
	this->mCodeGen->Generate(codenz);
	
	// Display generated code inside window.
	this->mCodeField.Set(codenz);
}

// Executed when the dialog is closed.
void CryCodeGenerationForm::CloseForm()
{
	this->Close();
}