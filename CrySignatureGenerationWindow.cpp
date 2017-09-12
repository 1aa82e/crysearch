#include "CrySignatureGenerationWindow.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"

// This window needs access to the visible disassembly lines.
extern Vector<LONG_PTR> DisasmVisibleLines;

// The CrySignatureGenerationWindow default constructor, accepting a number of selected rows.
CrySignatureGenerationWindow::CrySignatureGenerationWindow(const Vector<int>& rows) : CryDialogTemplate(CrySearchIml::GenerateSignatureButton())
{
	this->Title("Generate Signature").SetRect(0, 0, 320, 200);
	
	this->mClose <<= THISBACK(CloseWindow);
	this->mShouldMask.WhenAction = THISBACK(ShouldMaskToggle);
	
	*this
		<< this->mStringStyleSection.SetLabel("String style").HSizePos(5, 5).TopPos(5, 110)
		<< this->mStringStyle.SetLabel("Signature:").LeftPos(10, 80).TopPos(25, 25)
		<< this->mStringStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(25, 25)
		<< this->mShouldMask.SetLabel("Automatically mask arguments").HSizePos(10, 10).TopPos(50, 25)
		<< this->mStringMask.SetLabel("Mask:").LeftPos(10, 80).TopPos(80, 25)
		<< this->mStringMaskSig.HSizePos(90, 10).TopPos(80, 25)
		<< this->mBytesStyleSection.SetLabel("Bytes style").HSizePos(5, 5).TopPos(115, 50)
		<< this->mBytesStyle.SetLabel("Signature:").LeftPos(10, 80).TopPos(135, 25)
		<< this->mBytesStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(135, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 70).BottomPos(5, 25)
	;
	
	// Retrieve byte sets that are selected.
	Vector<Byte> byteSets;
	const int count = rows.GetCount();
	for (int i = 0; i < count; ++i)
	{
		// Get the bytes for the instruction at the current index.
		ArrayOfBytes sequence;
		Vector<char> localMask;
		
		// Disassemble the current line.
#ifdef _WIN64
		DisasmForBytes(DisasmVisibleLines[rows[i]], mMemoryScanner->IsX86Process() ? CS_MODE_32 : CS_MODE_64, &sequence, &localMask);
#else
		DisasmForBytes(DisasmVisibleLines[rows[i]], CS_MODE_32, &sequence, &localMask);
#endif
		
		// Append the retrieved mask to the global mask.
		this->maskInfo.Append(localMask);
		
		// Add the retrieved bytes to the internal byte set for generation.
		for (int y = 0; y < sequence.Size; ++y)
		{
			byteSets << sequence.Data[y];
		}
	}
	
	// Terminate the mask string.
	this->maskInfo << 0x0;
	
	// Set the masking option correctly.
	this->mShouldMask = SettingsFile::GetInstance()->GetSignatureMaskingByDefault();
	
	// Generate signatures in all supported styles.
	this->GenerateEvoStyle(byteSets);
	this->GenerateStringStyle(byteSets);
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
void CrySignatureGenerationWindow::GenerateStringStyle(const Vector<Byte>& aobs)
{
	// Set generated signature inside top textbox.
	this->mStringStyleSig.SetText(GenerateStringStyleSignature(aobs));
	
	// Set the mask string in the user interface.
	this->ShouldMaskToggle();
}

// Executed when the dialog is closed.
void CrySignatureGenerationWindow::CloseWindow()
{
	this->Close();
}

// Executed when the user toggles the mask option.
void CrySignatureGenerationWindow::ShouldMaskToggle()
{
	// Check whether the user enabled or disabled masking.
	if (this->mShouldMask)
	{
		// Set the mask string in the user interface.
		this->mStringMaskSig.SetText(this->maskInfo);
	}
	else
	{
		// Set the mask with x's.
		this->mStringMaskSig.SetText(String('x', this->maskInfo.GetCount()));
	}
}