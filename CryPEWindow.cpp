#include "CryPEWindow.h"
#include "ImlProvider.h"
#include "FrontendGlobalDef.h"
#include "BackendGlobalDef.h"

String GetPEFieldKey(const int index)
{
	return LoadedProcessPEInformation.PEFields.GetKey(index);
}

String GetPEFieldValue(const int index)
{
	return LoadedProcessPEInformation.PEFields.Get(LoadedProcessPEInformation.PEFields.GetKey(index)).ToString();
}

String GetSectionName(const int index)
{
	return LoadedProcessPEInformation.ImageSections[index].SectionName;
}

String GetSectionBaseAddress(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((__int64)LoadedProcessPEInformation.ImageSections[index].BaseAddress);
#else
	return FormatIntHexUpper((int)LoadedProcessPEInformation.ImageSections[index].BaseAddress, 0);
#endif
}

String GetSectionVirtualSize(const int index)
{
#ifdef _WIN64
	return FormatInt64HexUpper((__int64)LoadedProcessPEInformation.ImageSections[index].SectionSize);
#else
	return FormatIntHexUpper((int)LoadedProcessPEInformation.ImageSections[index].SectionSize, 0);
#endif
}

String GetDotNetSectionName(const int index)
{
	return LoadedProcessPEInformation.DotNetInformation.DotNetSections[index].SectionName;
}

String GetDotNetSectionOffset(const int index)
{
	return Format("%lX", LoadedProcessPEInformation.DotNetInformation.DotNetSections[index].Offset);
}

String GetDotNetSectionSize(const int index)
{
	return Format("%lX", LoadedProcessPEInformation.DotNetInformation.DotNetSections[index].Size);
}

CryPEWindow::CryPEWindow()
{
	this->AddFrame(this->mToolStrip);
	
	this->mPeInformationCtrl.CryAddRowNumColumn("Field").SetConvert(Single<IndexBasedValueConvert<GetPEFieldKey>>());
	this->mPeInformationCtrl.CryAddRowNumColumn("Value").SetConvert(Single<IndexBasedValueConvert<GetPEFieldValue>>());
	
	this->mSections.CryAddRowNumColumn("Name").SetConvert(Single<IndexBasedValueConvert<GetSectionName>>());
	this->mSections.CryAddRowNumColumn("Virtual Address").SetConvert(Single<IndexBasedValueConvert<GetSectionBaseAddress>>());
	this->mSections.CryAddRowNumColumn("Virtual Size").SetConvert(Single<IndexBasedValueConvert<GetSectionVirtualSize>>());
	this->mSections.WhenBar = THISBACK(SectionsListRightClick);
	this->mSections.WhenSel = THISBACK(SectionsListSelectionChanged);
	
	this->mDotNetInformation.CryAddRowNumColumn("Name").SetConvert(Single<IndexBasedValueConvert<GetDotNetSectionName>>());
	this->mDotNetInformation.CryAddRowNumColumn("Offset").SetConvert(Single<IndexBasedValueConvert<GetDotNetSectionOffset>>());
	this->mDotNetInformation.CryAddRowNumColumn("Size").SetConvert(Single<IndexBasedValueConvert<GetDotNetSectionSize>>());
	this->mDotNetInformation.WhenBar = THISBACK(DotNetSectionsListRightClick);
	
	this->mSplitter.SetMinPixels(0, 200);
	this->mSplitter.SetMinPixels(1, 200);
	
	this->mRightPaneSplitter.SetMinPixels(0, 100);
	this->mRightPaneSplitter.SetMinPixels(1, 100);
}

CryPEWindow::~CryPEWindow()
{
	
}

void CryPEWindow::ToolBar(Bar& pBar)
{
	pBar.Add("Refresh", CrySearchIml::RefreshButtonSmall(), THISBACK(RefreshPEWindow));
	pBar.ToolGapRight();
	pBar.Add(this->mSections.IsCursor(), "Dump Section", CrySearchIml::DumpModuleSmall(), THISBACK(DumpSection));
	
	// If a suspended process was created, a button to resume the process should be visible to the user
	// straight away. Using the Threads window is not straight forward.
	if (mMemoryScanner && mMemoryScanner->IsProcessSuspended())
	{
		pBar.Add("Resume Process", CrySearchIml::ResumeAllThreadsSmall(), THISBACK(ResumeSuspendedProcess));
	}
}

void CryPEWindow::SectionsListRightClick(Bar& pBar)
{
	if (this->mSections.GetCursor() >= 0 && LoadedProcessPEInformation.PEFields.GetCount() > 0)
	{
		pBar.Add("Dump Section", CrySearchIml::DumpModuleSmall(), THISBACK(DumpSection));
	}
}

void CryPEWindow::DotNetSectionsListRightClick(Bar& pBar)
{
	if (this->mSections.GetCursor() >= 0 && LoadedProcessPEInformation.PEFields.GetCount() > 0)
	{
		pBar.Add("Dump Section", CrySearchIml::DumpModuleSmall(), THISBACK(DumpDotNetSection));
	}
}

void CryPEWindow::SectionsListSelectionChanged()
{
	this->mToolStrip.Set(THISBACK(ToolBar));
}

void CryPEWindow::RefreshPEWindow()
{
	this->Initialize();
}

void CryPEWindow::ResumeSuspendedProcess()
{
	// Resume suspended process by iterating all suspended threads and resuming them.
	const int tCount = mThreadsList.GetCount();
	for (int i = 0; i < tCount; ++i)
	{
		CryResumeThread(mThreadsList[i].ThreadIdentifier);
	}
	
	// Sleep for a short unnoticable time to let the process build up.
	Sleep(100);
	
	// Reload the toolbar to remove the gap and button.
	mMemoryScanner->ResetSuspendedState();
	this->mToolStrip.Set(THISBACK(ToolBar));
	
	// Reload tab window contents.
	mCrySearchWindowManager->ClearWindows();
	mCrySearchWindowManager->GetModuleWindow()->Initialize();
	mCrySearchWindowManager->GetThreadWindow()->Initialize();
	mCrySearchWindowManager->GetImportsWindow()->Initialize();
	mCrySearchWindowManager->GetDisasmWindow()->Initialize();
	mCrySearchWindowManager->GetPEWindow()->Initialize();	
}

void CryPEWindow::Initialize()
{
	// On window initialization, reset toolbar.
	this->mToolStrip.Set(THISBACK(ToolBar));
	
	// Get executable file PE information.
	if (mModuleManager->GetModuleCount() > 0)
	{
		mPeInstance->GetExecutablePeInformation();
	}
	
	this->mPeInformationCtrl.SetVirtualCount(LoadedProcessPEInformation.PEFields.GetCount());
	this->mSections.SetVirtualCount(LoadedProcessPEInformation.ImageSections.GetCount());
	this->mDotNetInformation.SetVirtualCount(LoadedProcessPEInformation.DotNetInformation.DotNetSections.GetCount());
	
	// Depending on the type of file, the lower right pane may or may not be visible.
	*this
		<< this->mSplitter.Horz(this->mPeInformationCtrl.SizePos(), LoadedProcessPEInformation.DotNetInformation.DotNetSections.GetCount() > 0 ? 
			this->mRightPaneSplitter.Vert(this->mSections.SizePos(), this->mDotNetInformation.SizePos()) : this->mSections.SizePos())
	;
}

void CryPEWindow::ClearList()
{
	LoadedProcessPEInformation.Reset();
	this->mPeInformationCtrl.SetVirtualCount(0);
	this->mSections.SetVirtualCount(0);
	this->mDotNetInformation.SetVirtualCount(0);
}

void CryPEWindow::DumpSection()
{
	const int row = this->mSections.GetCursor();
	if (row >= 0 && LoadedProcessPEInformation.ImageSections.GetCount() > 0)
	{
		FileSel* fs = new FileSel();
		fs->Types("Memory Dump files\t*.dmp");
		
		if (fs->ExecuteSaveAs("Select dump directory"))
		{
			const Win32PESectionInformation& sect = LoadedProcessPEInformation.ImageSections[row];
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
	}
}

void CryPEWindow::DumpDotNetSection()
{
	const int row = this->mDotNetInformation.GetCursor();
	if (row >= 0 && LoadedProcessPEInformation.DotNetInformation.DotNetSections.GetCount() > 0)
	{
		FileSel* fs = new FileSel();
		fs->Types("Memory Dump files\t*.dmp");
		
		if (fs->ExecuteSaveAs("Select dump directory"))
		{
			const Win32DotNetSectionInformation& sect = LoadedProcessPEInformation.DotNetInformation.DotNetSections[row];
			if (mPeInstance->DumpProcessSection(fs->Get(), LoadedProcessPEInformation.DotNetInformation.MetadataHeaderOffset + sect.Offset, sect.Size))
			{
				PromptOK("Dump succeeded!");
			}
			else
			{
				Prompt("Dumping error", CtrlImg::error(), "Failed to dump the section. Either the memory failed to read of the file could not be created.", "OK");
			}
		}
		
		delete fs;
	}
}