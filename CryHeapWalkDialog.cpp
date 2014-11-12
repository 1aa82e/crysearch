#include "CryHeapWalkDialog.h"
#include "ProcessUtil.h"

CryHeapWalkDialog::CryHeapWalkDialog(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("Heap Walk").Sizeable().SetRect(0, 0, 550, 200);
	
	this->mHeapList.CryAddColumn("Virtual address", 28);
	this->mHeapList.CryAddColumn("Committed size", 22);
	this->mHeapList.CryAddColumn("Allocated size", 20);
	this->mHeapList.CryAddColumn("Block count", 25);
	this->mHeapList.CryAddColumn("Flags", 15);
	
	this->mClose <<= THISBACK(CloseDialog);
	
	*this
		<< this->mHeapList.HSizePos(5, 5).VSizePos(5, 35)
		<< this->mHeapCount.LeftPos(5, 100).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 60).BottomPos(5, 25)
	;
	
	// Call heap enumeration function and put data inside UI parts to visualize.
	Vector<Win32HeapInformation> heaps;
	if (EnumerateHeaps(heaps))
	{
		for (int i = 0; i < heaps.GetCount(); ++i)
		{
			this->mHeapList.Add(Format("%llX", heaps[i].VirtualAddress), Format("%llX", heaps[i].CommittedSize), Format("%llX", heaps[i].AllocatedSize)
				, Format("%llX", heaps[i].BlockCount), Format("%llX", heaps[i].Flags));
		}
	}
	else
	{
		this->mHeapList.Add("Heap walk failed");
	}
	
	// Set the amount of heaps in a label.
	this->mHeapCount.SetLabel(Format("Total %i heaps", heaps.GetCount()));
}

CryHeapWalkDialog::~CryHeapWalkDialog()
{
	
}

void CryHeapWalkDialog::CloseDialog()
{
	this->Close();
}