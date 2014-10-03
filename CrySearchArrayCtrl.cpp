#include "CrySearchArrayCtrl.h"

// Returns a range of visible items in an array control.
Tuple2<int, int> CrySearchArrayCtrl::GetVisibleRange()
{
	int from = 0;
	int to = 0;
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

// Sets the same display structure for every cell in a row.
// The first parameter is the row and the second parameter is the display structure.
// This function requires protected access to the cellinfo vector.
void CrySearchArrayCtrl::SetRowDisplay(int i, const Display& d)
{
	const int rowCount = this->GetCount();
	const int colCount = this->GetColumnCount();
	if(i >= 0 && i < rowCount)
	{
		for (int j = 0 ; j < colCount; ++j)
		{
			this->cellinfo.At(i).At(j).Set(d);
		}
	}
	
	this->RefreshRow(i);
}
