#include "CryByteArrayGenerationWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "BackendGlobalDef.h"

// This window needs access to the visible disassembly lines.
extern Vector<LONG_PTR> DisasmVisibleLines;

CryByteArrayGenerationWindow::CryByteArrayGenerationWindow(const Vector<int>& rows) : CryDialogTemplate(CrySearchIml::GenerateByteArrayButton())
{
	this->Title("Generate Byte-array").SetRect(0, 0, 300, 130);
	
	this->mClose <<= THISBACK(CloseWindow);
	
	*this
		<< this->mCPPStyleSection.SetLabel("C++").HSizePos(5, 5).TopPos(5, 40)
		<< this->mCPPStyle.SetLabel("Byte-array:").LeftPos(10, 80).TopPos(20, 20)
		<< this->mCPPStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(20, 20)
		<< this->mCSharpStyleSection.SetLabel("C#").HSizePos(5, 5).TopPos(50, 40)
		<< this->mCSharpStyle.SetLabel("Byte-array:").LeftPos(10, 80).TopPos(65, 20)
		<< this->mCSharpStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(65, 20)
		<< this->mClose.SetLabel("Close").RightPos(5, 60).BottomPos(5, 25)
	;
	
	// Retrieve byte sets that are selected.
	Vector<Byte> byteSets;
	for (int i = 0; i < rows.GetCount(); ++i)
	{
		ArrayOfBytes sequence;
#ifdef _WIN64
		DisasmGetLine(DisasmVisibleLines[rows[i]], mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, &sequence);
#else
		DisasmGetLine(DisasmVisibleLines[rows[i]], ARCH_X86, &sequence);
#endif
		for (int y = 0; y < sequence.Size; ++y)
		{
			byteSets << sequence.Data[y];
		}
	}
	
	// Generate signatures in all supported styles.
	this->GenerateCPPStyle(byteSets);
	this->GenerateCSharpStyle(byteSets);
}

CryByteArrayGenerationWindow::~CryByteArrayGenerationWindow()
{
	
}

void CryByteArrayGenerationWindow::GenerateCPPStyle(const Vector<Byte>& aobs)
{
	// Set the string in the user interface controls.
	this->mCPPStyleSig.SetText(GenerateByteArray(aobs, ARRAYTYPE_CPP));
}

void CryByteArrayGenerationWindow::GenerateCSharpStyle(const Vector<Byte>& aobs)
{
	// Set generated signature inside top textbox.
	this->mCSharpStyleSig.SetText(GenerateByteArray(aobs, ARRAYTYPE_CSHARP));
}

void CryByteArrayGenerationWindow::CloseWindow()
{
	this->Close();
}
