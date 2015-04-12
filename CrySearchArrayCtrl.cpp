#include "CrySearchArrayCtrl.h"

// Handles the DEL key for each array control in the application.
bool CrySearchArrayCtrl::Key(dword key, int count)
{
	// Check for DEL key presses.
	if (key == K_DELETE)
	{
		// Execute the removal routine. Since we make such intensive use of virtual rows, we 
		// can't place responsibility at the control itself.
		Vector<int> selectedRows;
		for (int i = 0; i < this->GetCount(); ++i)
		{
			if (this->IsSelected(i))
			{
				selectedRows << i;
			}
		}
		
		// If the removal routine was implemented, execute it. Otherwise, the DEL key does nothing.
		if (this->RemovalRoutine)
		{
			this->RemovalRoutine(selectedRows);
		}
		return true;
	}
	
	// Execute base key function of the ArrayCtrl class.
	return ArrayCtrl::Key(key, count);
}

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

// Proxying method for adding a regular ArrayCtrl column. Sets a minimum width for a new column.
ArrayCtrl::Column& CrySearchArrayCtrl::CryAddColumn(const char *text, int w)
{
	ArrayCtrl::Column& col = this->AddColumn(text, w);
	col.HeaderTab().Min(25);
	return col;
}

// Proxying method for adding a virtual data column. Sets a minimum width for a new column.
ArrayCtrl::Column& CrySearchArrayCtrl::CryAddRowNumColumn(const char *text, int w)
{
	ArrayCtrl::Column& col = this->AddRowNumColumn(text, w);
	col.HeaderTab().Min(25);
	return col;
}