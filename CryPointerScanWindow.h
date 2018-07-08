#ifndef _CrySearch_CryPointerScanWindow_h_
#define _CrySearch_CryPointerScanWindow_h_

#include "CryDialogTemplate.h"

// Dialog that implements pointer scanning functionality.
class CryPointerScanWindow : public CryDialogTemplate
{
private:
	typedef CryPointerScanWindow CLASSNAME;
public:
	CryPointerScanWindow(const Image& icon);
	~CryPointerScanWindow();
};

#endif