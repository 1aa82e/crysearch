#ifndef _CrySearch_CrySignatureGenerationWindow_h_
#define _CrySearch_CrySignatureGenerationWindow_h_

#include "CryDialogTemplate.h"
#include "Disassembler.h"

class CrySignatureGenerationWindow : public CryDialogTemplate
{
private:
	Button mClose;
	LabelBox mStringStyleSection;
	Label mStringStyle;
	EditField mStringStyleSig;
	Label mStringMask;
	EditField mStringMaskSig;
	LabelBox mBytesStyleSection;
	Label mBytesStyle;
	EditField mBytesStyleSig;
	
	void CloseWindow();
	
	void GenerateEvoStyle(const Vector<ArrayOfBytes*>& aobs);
	void GenerateStringStyle(const Vector<ArrayOfBytes*>& aobs);
	
	typedef CrySignatureGenerationWindow CLASSNAME;
public:
	CrySignatureGenerationWindow(const Vector<int>& rows);
	~CrySignatureGenerationWindow();
};

#endif