#ifndef _CrySearch_CrySearchArrayCtrl_h_
#define _CrySearch_CrySearchArrayCtrl_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

// Represents a customized ArrayCtrl to fit CrySearch user interface needs.
class CrySearchArrayCtrl : public ArrayCtrl
{
public:
	Tuple2<int, int> GetVisibleRange();
	void SetRowDisplay(int i, const Display& d);
	
	ArrayCtrl::Column& CryAddColumn(const char *text = NULL, int w = 0);
	ArrayCtrl::Column& CryAddRowNumColumn(const char *text, int w = 0);
};

#endif