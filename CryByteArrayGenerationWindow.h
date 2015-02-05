#ifndef _CrySearch_CryByteArrayGenerationWindow_h_
#define _CrySearch_CryByteArrayGenerationWindow_h_

#include "CryDialogTemplate.h"

class CryByteArrayGenerationWindow : public CryDialogTemplate
{
private:
	Button mClose;
	LabelBox mCPPStyleSection;
	Label mCPPStyle;
	EditField mCPPStyleSig;
	LabelBox mCSharpStyleSection;
	Label mCSharpStyle;
	EditField mCSharpStyleSig;
	
	void CloseWindow();
	
	void GenerateCPPStyle(const Vector<Byte>& aobs);
	void GenerateCSharpStyle(const Vector<Byte>& aobs);
	
	typedef CryByteArrayGenerationWindow CLASSNAME;
public:
	CryByteArrayGenerationWindow(const Vector<int>& rows);
	~CryByteArrayGenerationWindow();
};

#endif