#ifndef _CrySearch_CrySignatureGenerationWindow_h_
#define _CrySearch_CrySignatureGenerationWindow_h_

#include "CryDialogTemplate.h"
#include "UIUtilities.h"

// When a process' code is disassembled, signatures can be generated from this window.
class CrySignatureGenerationWindow : public CryDialogTemplate
{
private:
	Vector<char> maskInfo;
	
	Button mClose;
	LabelBox mStringStyleSection;
	Label mStringStyle;
	EditField mStringStyleSig;
	Label mStringMask;
	Option mShouldMask;
	EditField mStringMaskSig;
	LabelBox mBytesStyleSection;
	Label mBytesStyle;
	EditField mBytesStyleSig;
	
	void CloseWindow();
	void ShouldMaskToggle();
	
	void GenerateEvoStyle(const Vector<Byte>& aobs);
	void GenerateStringStyle(const Vector<Byte>& aobs);
	
	typedef CrySignatureGenerationWindow CLASSNAME;
public:
	CrySignatureGenerationWindow(const Vector<int>& rows);
	~CrySignatureGenerationWindow();
};

#endif