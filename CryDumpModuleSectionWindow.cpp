#include "CryDumpModuleSectionWindow.h"
#include "GlobalDef.h"

CryDumpModuleSectionWindow::CryDumpModuleSectionWindow(const int modListIndex)
{
	this->Title("Dump Section").Sizeable().SetRect(0, 0, 300, 200);
	
	this->mDumpButton <<= THISBACK(DumpSelectedSection);
	this->mCancelButton <<= THISBACK(CancelAndCloseDialog);
	
	this->mSectionsList.AddColumn("Name");
	this->mSectionsList.AddColumn("Address");
	this->mSectionsList.AddColumn("Size");
	
	*this
		<< this->mSectionsList.HSizePos(5, 5).VSizePos(5, 35)
		<< this->mSectionCount.LeftPos(5, 100).BottomPos(5, 25)
		<< this->mCancelButton.SetLabel("Cancel").RightPos(5, 60).BottomPos(5, 25)
		<< this->mDumpButton.SetLabel("Dump").RightPos(70, 60).BottomPos(5, 25)
	;
	
	// Retrieve information about the module that was passed into the form.
	this->mModuleInfo = &LoadedModulesList[modListIndex];
	
	// Get the sections associated to the module.
	Byte* moduleBuffer = new Byte[0x400];
	CrySearchRoutines.CryReadMemoryRoutine(mMemoryScanner->GetHandle(), (void*)this->mModuleInfo->BaseAddress, moduleBuffer, 0x400, NULL);
	
#ifdef _WIN64
	if (mMemoryScanner->IsX86Process())
	{
		const IMAGE_NT_HEADERS32* pNtHeaders = (IMAGE_NT_HEADERS32*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
		mPeInstance->GetImageSectionsList(IMAGE_FIRST_SECTION(pNtHeaders), pNtHeaders->FileHeader.NumberOfSections, this->imageSections);
	}
	else
	{
		const IMAGE_NT_HEADERS64* pNtHeaders = (IMAGE_NT_HEADERS64*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
		mPeInstance->GetImageSectionsList(IMAGE_FIRST_SECTION(pNtHeaders), pNtHeaders->FileHeader.NumberOfSections, this->imageSections);
	}
#else
	const IMAGE_NT_HEADERS32* pNtHeaders = (IMAGE_NT_HEADERS32*)(moduleBuffer + ((IMAGE_DOS_HEADER*)moduleBuffer)->e_lfanew);
	mPeInstance->GetImageSectionsList(IMAGE_FIRST_SECTION(pNtHeaders), pNtHeaders->FileHeader.NumberOfSections, this->imageSections);
#endif

	delete[] moduleBuffer;
	
	for (int i = 0; i < this->imageSections.GetCount(); ++i)
	{
		const Win32PESectionInformation& cur = this->imageSections[i];
		this->mSectionsList.Add(cur.SectionName, Format("%llX", (__int64)cur.BaseAddress), Format("%llX", (__int64)cur.SectionSize));
	}
	
	// Set the amount of sections in a label.
	this->mSectionCount.SetLabel(Format("Total %i sections", this->imageSections.GetCount()));
}

CryDumpModuleSectionWindow::~CryDumpModuleSectionWindow()
{
	
}

void CryDumpModuleSectionWindow::DumpSelectedSection()
{
	const int cursorRow = this->mSectionsList.GetCursor();
	if (cursorRow >= 0 && cursorRow < this->mSectionsList.GetCount())
	{
		FileSel* fs = new FileSel();
		fs->Types("Memory Dump files\t*.dmp");
		if (fs->ExecuteSaveAs("Select dump location"))
		{
			const Win32PESectionInformation& sect = this->imageSections[cursorRow];
			if (mPeInstance->DumpProcessSection(fs->Get(), sect.BaseAddress, sect.RawSectionSize ? sect.RawSectionSize : sect.SectionSize))
			{
				PromptOK("Dump succeeded!");
			}
			else
			{
				Prompt("Dumping error", CtrlImg::error(), "Failed to dump the section. Either the memory failed to read of the file could not be created.", "OK");
			}
		}
		
		delete fs;
		this->Close();
	}
	else
	{
		Prompt("Input Error", CtrlImg::error(), "Please select a section to dump.", "OK");
	}
}

void CryDumpModuleSectionWindow::CancelAndCloseDialog()
{
	this->Close();
}