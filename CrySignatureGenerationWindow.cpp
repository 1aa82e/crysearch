#include "CrySignatureGenerationWindow.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"

// This window needs access to the visible disassembly lines.
extern Vector<LONG_PTR> DisasmVisibleLines;

// The CrySignatureGenerationWindow default constructor, accepting a number of selected rows.
CrySignatureGenerationWindow::CrySignatureGenerationWindow(const Vector<int>& rows) : CryDialogTemplate(CrySearchIml::GenerateSignatureButton())
{
	this->Title("Generate Signature").SetRect(0, 0, 300, 175);
	
	this->mClose <<= THISBACK(CloseWindow);
	
	*this
		<< this->mStringStyleSection.SetLabel("String style").HSizePos(5, 5).TopPos(5, 85)
		<< this->mStringStyle.SetLabel("Signature:").LeftPos(10, 80).TopPos(25, 25)
		<< this->mStringStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(25, 25)
		<< this->mStringMask.SetLabel("Mask:").LeftPos(10, 80).TopPos(55, 25)
		<< this->mStringMaskSig.HSizePos(90, 10).TopPos(55, 25)
		<< this->mBytesStyleSection.SetLabel("Bytes style").HSizePos(5, 5).TopPos(90, 50)
		<< this->mBytesStyle.SetLabel("Signature:").LeftPos(10, 80).TopPos(110, 25)
		<< this->mBytesStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(110, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 70).BottomPos(5, 25)
	;
	
	// Retrieve byte sets that are selected.
	Vector<Byte> byteSets;
	Vector<char> maskInfo;
	const int count = rows.GetCount();
	for (int i = 0; i < count; ++i)
	{
		// Get the bytes for the instruction at the current index.
		ArrayOfBytes sequence;
		Vector<char> localMask;
		
		// Disassemble the current line.
#ifdef _WIN64
		DisasmForBytes(DisasmVisibleLines[rows[i]], mMemoryScanner->IsX86Process() ? ARCH_X86 : ARCH_X64, &sequence, &localMask);
#else
		DisasmForBytes(DisasmVisibleLines[rows[i]], ARCH_X86, &sequence, &localMask);
#endif
		
		// Append the retrieved mask to the global mask.
		maskInfo.Append(localMask);
		
		// Add the retrieved bytes to the internal byte set for generation.
		for (int y = 0; y < sequence.Size; ++y)
		{
			byteSets << sequence.Data[y];
		}
	}
	
	// Terminate the mask string.
	maskInfo << 0x0;
	
	// Generate signatures in all supported styles.
	this->GenerateEvoStyle(byteSets);
	this->GenerateStringStyle(byteSets, maskInfo);
}

// The CrySignatureGenerationWindow default destructor.
CrySignatureGenerationWindow::~CrySignatureGenerationWindow()
{
	
}

// Generates a byte-style (evo-style) signature, that looks like an IDA Pro style signature.
void CrySignatureGenerationWindow::GenerateEvoStyle(const Vector<Byte>& aobs)
{
	// Manually concatenate the bytes into one string.
	String uiText = BytesToString(aobs.Begin(), aobs.GetCount());
	
	// Set the string in the user interface controls.
	this->mBytesStyleSig.SetText(uiText);
}

// Generates a conventional signature, including a mask.
void CrySignatureGenerationWindow::GenerateStringStyle(const Vector<Byte>& aobs, const Vector<char>& mask)
{
	// Set generated signature inside top textbox.
	this->mStringStyleSig.SetText(GenerateStringStyleSignature(aobs));
	
	// Set the mask string in the user interface.
	this->mStringMaskSig.SetText(mask);
}

// Executed when the dialog is closed.
void CrySignatureGenerationWindow::CloseWindow()
{
	this->Close();
}