#include "CrySignatureGenerationWindow.h"
#include "ImlProvider.h"
#include "UIUtilities.h"

// This window needs access to the visible disassembly lines.
extern Vector<DisasmLine> DisasmVisibleLines;

CrySignatureGenerationWindow::CrySignatureGenerationWindow(const Vector<int>& rows) : CryDialogTemplate(CrySearchIml::GenerateSignatureButton())
{
	this->Title("Generate Signature").SetRect(0, 0, 300, 150);
	
	this->mClose <<= THISBACK(CloseWindow);
	
	*this
		<< this->mStringStyleSection.SetLabel("String style").HSizePos(5, 5).TopPos(5, 65)
		<< this->mStringStyle.SetLabel("Signature:").LeftPos(10, 80).TopPos(20, 20)
		<< this->mStringStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(20, 20)
		<< this->mStringMask.SetLabel("Mask:").LeftPos(10, 80).TopPos(45, 20)
		<< this->mStringMaskSig.HSizePos(90, 10).TopPos(45, 20)
		<< this->mBytesStyleSection.SetLabel("Bytes style").HSizePos(5, 5).TopPos(70, 40)
		<< this->mBytesStyle.SetLabel("Signature:").LeftPos(10, 80).TopPos(85, 20)
		<< this->mBytesStyleSig.SetEditable(false).HSizePos(90, 10).TopPos(85, 20)
		<< this->mClose.SetLabel("Close").RightPos(5, 60).BottomPos(5, 25)
	;
	
	// Retrieve byte sets that are selected.
	Vector<ArrayOfBytes*> byteSets;
	for (int i = 0; i < rows.GetCount(); ++i)
	{
		byteSets.Add(&DisasmVisibleLines[rows[i]].BytesStringRepresentation);
	}
	
	// Generate signatures in all supported styles.
	this->GenerateEvoStyle(byteSets);
	this->GenerateStringStyle(byteSets);
}

CrySignatureGenerationWindow::~CrySignatureGenerationWindow()
{
	
}

void CrySignatureGenerationWindow::GenerateEvoStyle(const Vector<ArrayOfBytes*>& aobs)
{
	// Manually concatenate the byte arrays into one string.
	String uiText;
	for (int i = 0; i < aobs.GetCount(); ++i)
	{
		const ArrayOfBytes* aob = aobs[i];
		uiText += BytesToString(aob->Data, aob->Size) + " ";
	}
	
	// Remove the last space from the string.
	uiText.Remove(uiText.GetCount() - 1);
	
	// Set the string in the user interface controls.
	this->mBytesStyleSig.SetText(uiText);
}

void CrySignatureGenerationWindow::GenerateStringStyle(const Vector<ArrayOfBytes*>& aobs)
{
	// Set generated signature inside top textbox.
	DWORD maskLength;
	this->mStringStyleSig.SetText(GenerateStringStyleSignature(aobs, &maskLength));
	
	// Generate mask accordingly.
	this->mStringMaskSig.SetText(String(0x78, maskLength));
}

void CrySignatureGenerationWindow::CloseWindow()
{
	this->Close();
}