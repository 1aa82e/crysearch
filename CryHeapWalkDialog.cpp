#include "CryHeapWalkDialog.h"
#include "BackendGlobalDef.h"
#include "UIUtilities.h"

// The CryHeapWalkDialog default constructor.
CryHeapWalkDialog::CryHeapWalkDialog(const Image& icon) : CryDialogTemplate(icon)
{
	this->Title("View Heap Information").Sizeable().SetRect(0, 0, 550, 200);
	
	this->mHeapList.CryAddColumn("Virtual address", 28);
	this->mHeapList.CryAddColumn("Committed size", 22);
	this->mHeapList.CryAddColumn("Allocated size", 20);
	this->mHeapList.CryAddColumn("Block count", 25);
	this->mHeapList.CryAddColumn("Flags", 15);
	this->mHeapList.WhenBar = THISBACK(HeapsRightClicked);
	
	this->mClose <<= THISBACK(CloseDialog);
	
	*this
		<< this->mHeapList.HSizePos(5, 5).VSizePos(5, 35)
		<< this->mHeapCount.LeftPos(5, 100).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 70).BottomPos(5, 25)
	;
	
	// Call heap enumeration function and put data inside UI parts to visualize.
	if (EnumerateHeaps(this->mHeaps))
	{
		for (auto const& heap : this->mHeaps)
		{
			this->mHeapList.Add(FormatInt64HexUpper(heap.VirtualAddress), FormatInt64HexUpper(heap.CommittedSize), FormatInt64HexUpper(heap.AllocatedSize)
				, FormatInt64HexUpper(heap.BlockCount), FormatInt64HexUpper(heap.Flags));
		}
	}
	else
	{
		this->mHeapList.Add("Heap walk failed");
	}
	
	// Set the amount of heaps in a label.
	this->mHeapCount.SetLabel(Format("Total %i heaps", this->mHeaps.GetCount()));
}

// The CryHeapWalkDialog default destructor.
CryHeapWalkDialog::~CryHeapWalkDialog()
{
	
}

// Executed when the dialog is closed.
void CryHeapWalkDialog::CloseDialog()
{
	this->Close();
}

// Executed when the heap list is right-clicked.
void CryHeapWalkDialog::HeapsRightClicked(Bar& pBar)
{
	if (this->mHeapList.GetCursor() >= 0 && this->mHeaps.GetCount() > 0)
	{
		pBar.Add("Dump Heap", THISBACK(DumpSelectedHeap));
	}
}

// Attempts to dump the selected heap from memory into a file.
void CryHeapWalkDialog::DumpSelectedHeap()
{
	const int row = this->mHeapList.GetCursor();
	if (this->mHeapList.GetCursor() >= 0 && this->mHeaps.GetCount() > 0)
	{
		FileSel* fs = new FileSel();
		fs->Types("Memory Dump files\t*.dmp");
		
		if (fs->ExecuteSaveAs("Select dump directory"))
		{
			const Win32HeapInformation& heap = this->mHeaps[row];
			if (mPeInstance->DumpProcessSection(fs->Get(), heap.VirtualAddress, heap.AllocatedSize))
			{
				PromptOK("Dump succeeded!");
			}
			else
			{
				Prompt("Fatal error", CtrlImg::error(), "Failed to dump the heap. Either we failed to read memory or the file could not be created.", "OK");
			}
		}
		
		delete fs;
	}
}