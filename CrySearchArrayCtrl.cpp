#include "CrySearchArrayCtrl.h"

Tuple2<int, int> CrySearchArrayCtrl::GetVisibleRange()
{
	int from, to;
	const int last = this->GetCount() - 1;

	if (last >= 0)
	{
		const int cy = this->GetSize().cy - 1;
		const int sb = this->GetScroll();

		from = this->GetLineAt(sb),
		to = this->GetLineY(last) <= cy ? last : this->GetLineAt(sb + cy);
	}
	
	if (last < 0 || IsNull(to) || from > to)
	{
		from = to = -1;
	}

	return MakeTuple(from, to);
}

void CrySearchArrayCtrl::SetRowDisplay(int i, const Display& d)
{
	if(i >= 0 && i < this->GetCount())
	{
		for (int j = 0 ; j < this->GetSize().cx ; j++)
		{
			this->cellinfo.At(i).At(j).Set(d);
		}
	}
	
	this->RefreshRow(i);
}