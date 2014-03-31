#include "CryHeapWalkDialog.h"
#include "ProcessUtil.h"

CryHeapWalkDialog::CryHeapWalkDialog()
{
	this->Title("Heap Walk").SetRect(0, 0, 500, 200);
	
	this->mHeapList.AddColumn("Virtual address", 25);
	this->mHeapList.AddColumn("Committed size", 23);
	this->mHeapList.AddColumn("Allocated size", 22);
	this->mHeapList.AddColumn("Block count", 20);
	this->mHeapList.AddColumn("Flags", 10);
	
	this->mClose <<= THISBACK(CloseDialog);
	
	*this
		<< this->mHeapList.HSizePos(5, 5).VSizePos(5, 35)
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
}

CryHeapWalkDialog::~CryHeapWalkDialog()
{
	
}

bool CryHeapWalkDialog::Key(dword key, int count)
{
	if (key == K_ESCAPE)
	{
		this->Close();
		return true;
	}
	
	return false;
}

void CryHeapWalkDialog::CloseDialog()
{
	this->Close();
}