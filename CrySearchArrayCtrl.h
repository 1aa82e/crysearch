#ifndef _CrySearch_CrySearchArrayCtrl_h_
#define _CrySearch_CrySearchArrayCtrl_h_

#pragma warning(disable : 4005)

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

class CrySearchArrayCtrl : public ArrayCtrl
{
public:
	Tuple2<int, int> GetVisibleRange();
	void SetRowDisplay(int i, const Display& d);
};

#endif
