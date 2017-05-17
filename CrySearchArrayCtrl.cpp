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
		const int rowCount = this->GetCount();
		for (int i = 0; i < rowCount; ++i)
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