#include "CryCodeGenerationForm.h"
#include "ImlProvider.h"

CryCodeGenerationForm::CryCodeGenerationForm()
{
	this->Title("Generate Code").Icon(CrySearchIml::CodeGenerationButton()).Sizeable().SetRect(0, 0, 550, 400);
	
	this->mGenerate <<= THISBACK(GenerateButtonClicked);
	this->mClose <<= THISBACK(CloseForm);
	
	//this->mCreateExternalCode.WhenAction = THISBACK(ExternalCheckChanged);
	
	*this
		<< this->mLanguageSelectorLabel.SetLabel("Language:").LeftPos(5, 100).TopPos(5, 20)
		<< this->mLanguageSelector.Add("C++").LeftPos(80, 100).TopPos(5, 20)
		<< this->mCreateExternalCode.SetLabel("Generate external code (Win32 API's)").HSizePos(5, 5).TopPos(30, 20)
		<< this->mCodeField.HSizePos(5, 5).VSizePos(85, 30)
		<< this->mGenerate.SetLabel("Generate").RightPos(5, 75).TopPos(60, 20)
		<< this->mClose.SetLabel("Close").RightPos(5, 60).BottomPos(5, 20)
	;

	this->mLanguageSelector.SetIndex(0);
	
	// Create code generator
	this->mCodeGen = new CodeGenerator(&loadedTable);
}

CryCodeGenerationForm::~CryCodeGenerationForm()
{
	delete this->mCodeGen;
}

/*void CryCodeGenerationForm::ExternalCheckChanged()
{
	
}

void CryCodeGenerationForm::LanguageSelectionChanged()
{
	
}*/

void CryCodeGenerationForm::GenerateButtonClicked()
{
	this->mCodeGen->SetExternal(this->mCreateExternalCode);
	
	String codenz;
	this->mCodeGen->Generate(codenz);
	
	this->mCodeField.Set(codenz);
}

void CryCodeGenerationForm::CloseForm()
{
	this->Close();
}