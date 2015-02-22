#include "CryThreadWindow.h"
#include "ImlProvider.h"
#include "BackendGlobalDef.h"
#include "CryThreadChangePriorityWindow.h"
#include "CryCreateExternalThreadWindow.h"
#include "CryThreadInformationBlockWindow.h"
#include "CryThreadContextSnapWindow.h"
#include "UIUtilities.h"
#include "ProcessUtil.h"

Vector<Win32ThreadInformation> mThreadsList;

// External data source conversion functions.
String GetDecimalThreadId(const int index)
{
	return Format("%i", mThreadsList[index].ThreadIdentifier);
}

String GetHexadecimalThreadId(const int index)
{
	return Format("%X", mThreadsList[index].ThreadIdentifier);
}

String GetThreadPriority(const int index)
{
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, mThreadsList[index].ThreadIdentifier);
	String priorValue = CryGetThreadPriority(hThread);
	CloseHandle(hThread);
	return priorValue;
}

String GetThreadStartAddress(const int index)
{
	const Win32ModuleInformation* mod = NULL;
	const SIZE_T addr = mThreadsList[index].StartAddress;
	if (mod = mModuleManager->GetModuleFromContainedAddress(addr))
	{
		String modName = mModuleManager->GetModuleFilename(mod->BaseAddress);
		if (mDebugger->IsDebuggerAttached())
		{
			char symbolName[MAX_PATH];
			if (GetSingleSymbolName(mMemoryScanner->GetHandle(), addr, symbolName, MAX_PATH))
			{
				return Format("%s!%s", modName, symbolName);
			}
			else
			{
#ifdef _WIN64
				if (mMemoryScanner->IsX86Process())
				{
					return Format("%s!%lX", modName, (int)addr);
				}
				else
				{
					return Format("%s!%llX", modName, (__int64)addr);
				}
#else
				return Format("%s!%lX", modName, (int)addr);
#endif
			}
		}
		else
		{
#ifdef _WIN64
			if (mMemoryScanner->IsX86Process())
			{
				return Format("%s!%lX", modName, (int)addr);
			}
			else
			{
				return Format("%s!%llX", modName, (__int64)addr);
			}
#else
			return Format("%s!%lX", modName, (int)addr);
#endif			
		}
	}
	else
	{
#ifdef _WIN64
		if (mMemoryScanner->IsX86Process())
		{
			return FormatIntHexUpper((int)addr, 0);
		}
		else
		{
			return FormatInt64HexUpper((__int64)addr);
		}
#else
		return FormatIntHexUpper((int)addr, 0);
#endif
	}
}

CryThreadWindow::CryThreadWindow()
{
	this->AddFrame(this->tBar);
	this->tBar.Set(THISBACK(ToolBar));
	
	this->mThreads.CryAddRowNumColumn("ID (Decimal)", 20).SetConvert(Single<IndexBasedValueConvert<GetDecimalThreadId>>());
	this->mThreads.CryAddRowNumColumn("ID (Hex)", 20).SetConvert(Single<IndexBasedValueConvert<GetHexadecimalThreadId>>());
	this->mThreads.CryAddRowNumColumn("Priority", 20).SetConvert(Single<IndexBasedValueConvert<GetThreadPriority>>());
	this->mThreads.CryAddRowNumColumn("Start Address", 40).SetConvert(Single<IndexBasedValueConvert<GetThreadStartAddress>>());
	this->mThreads.WhenBar = THISBACK(ThreadListRightClick);
	
	*this << this->mThreads.SizePos();
}

CryThreadWindow::~CryThreadWindow()
{
	
}

void CryThreadWindow::Initialize()
{
	this->LoadThreads();
}

void CryThreadWindow::ToolBar(Bar& pBar)
{
	pBar.Add("Refresh thread list", CrySearchIml::RefreshButtonSmall(), THISBACK(LoadThreads));
	pBar.Add("Create thread in loaded process", CrySearchIml::AddToAddressList(), THISBACK(CreateExternalThread));
	pBar.Separator();
	pBar.Add("Attempt to suspend all threads", CrySearchIml::SuspendAllThreadsSmall(), THISBACK(AttemptSuspendAllThreads));
	pBar.Add("Attempt to resume all threads", CrySearchIml::ResumeAllThreadsSmall(), THISBACK(AttemptResumeAllThreads));
	pBar.ToolGapRight();
	pBar.Add(this->mThreadCount.SetAlign(ALIGN_RIGHT), 150);
}

void CryThreadWindow::ThreadListRightClick(Bar& pBar)
{
	const int threadRow = this->mThreads.GetCursor();
	if (threadRow >= 0 && mThreadsList.GetCount() > 0)
	{
		pBar.Add("View thread info", CrySearchIml::AboutButton(), THISBACK(ShowThreadInformationWindow));
		pBar.Add("Snap Context", CrySearchIml::SnapContextSmall(), THISBACK(SnapContextButtonClicked));
		pBar.Separator();
		pBar.Add("Suspend", CrySearchIml::SuspendButtonSmall(), THISBACK(SuspendThread));
		pBar.Add("Resume", CrySearchIml::ResumeButtonSmall(), THISBACK(ResumeThread));
		pBar.Add("Kill", CrySearchIml::DeleteButton(), THISBACK(TerminateThread));
		pBar.Separator();
		pBar.Add("Change Priority", CrySearchIml::ChangePrioritySmall(), THISBACK(ChangePriority));
	}
}

void CryThreadWindow::LoadThreads()
{
	EnumerateThreads(mMemoryScanner->GetProcessId(), mThreadsList);
	const int tCount = mThreadsList.GetCount();
	this->mThreads.SetVirtualCount(tCount);
	this->mThreadCount.SetLabel(Format("Total %i threads", tCount));
	
	// Set suspended thread row displays to red and running ones to standard.
	const int threadCount = mThreadsList.GetCount();
	for (int i = 0; i < threadCount; ++i)
	{
		this->mThreads.SetRowDisplay(i, mThreadsList[i].IsSuspended ? RedDisplayDrawInstance : StdDisplay());
	}
}

void CryThreadWindow::ClearList()
{
	mThreadsList.Clear();
	this->mThreads.SetVirtualCount(0);
}

void CryThreadWindow::AttemptSuspendAllThreads()
{
	const int tCount = mThreadsList.GetCount();
	for (int i = 0; i < tCount; ++i)
	{
		CrySuspendThread(mMemoryScanner->GetHandle(), mThreadsList[i].ThreadIdentifier);
	}
	
	// Refresh the thread list to review the suspended thread.
	this->LoadThreads();
}

void CryThreadWindow::AttemptResumeAllThreads()
{
	const int tCount = mThreadsList.GetCount();
	for (int i = 0; i < tCount; ++i)
	{
		CryResumeThread(mThreadsList[i].ThreadIdentifier);
	}
	
	// Refresh the thread list to review the suspended thread.
	this->LoadThreads();	
}

void CryThreadWindow::CreateExternalThread()
{
	CreateNewThreadStruct dataStruct;
	CryCreateExternalThreadWindow* newThreadWnd = new CryCreateExternalThreadWindow(&dataStruct, CrySearchIml::AddToAddressList());
	
	if (newThreadWnd->Execute() != 10)
	{
		delete newThreadWnd;
		return;
	}
	
	int outThreadId;
	switch (CryCreateExternalThread(mMemoryScanner->GetHandle(), dataStruct.StartAddress, dataStruct.ParameterPointer, dataStruct.StartSuspended, &outThreadId))
	{
		case 0: // succeeded
#ifdef _WIN64
			if (mMemoryScanner->IsX86Process())
			{
				if (dataStruct.StartSuspended)
				{
					PromptOK(Format("Thread created but suspended. Resume the thread manually to start it.&&Thread ID: %lX", outThreadId));
				}
				else
				{
					PromptOK(Format("Thread created and started!&&Thread ID: %lX", outThreadId));
				}
			}
			else
			{
				if (dataStruct.StartSuspended)
				{
					PromptOK(Format("Thread created but suspended. Resume the thread manually to start it.&&Thread ID: %llX", outThreadId));
				}
				else
				{
					PromptOK(Format("Thread created and started!&&Thread ID: %llX", outThreadId));
				}
			}
#else
			if (dataStruct.StartSuspended)
			{
				PromptOK(Format("Thread created but suspended. Resume the thread manually to start it.&&Thread ID: %lX", outThreadId));
			}
			else
			{
				PromptOK(Format("Thread created and started!&&Thread ID: %lX", outThreadId));
			}
#endif
			break;
		case -1: // failed to create the remote thread
			Prompt("Create Error", CtrlImg::error(), "The thread was not created because the system call failed.", "OK");
			break;
	}
	
	delete newThreadWnd;
	
	// Refresh the thread list to view the created thread.
	this->LoadThreads();
}

void CryThreadWindow::ChangePriority()
{
	int current = 2;
	const String& currentString = GetThreadPriority(this->mThreads.GetCursor());
	
	if (currentString == "Above Normal")
	{
		current = 4;
	}
	else if (currentString == "Below Normal")
	{
		current = 1;
	}
	else if (currentString == "Highest")
	{
		current = 5;
	}
	else if (currentString == "Idle")
	{
		current = 3;
	}
	else if (currentString == "Lowest")
	{
		current = 0;
	}
	else if (currentString == "Normal")
	{
		current = 2;
	}
	else if (currentString == "Realtime")
	{
		current = 6;
	}

	CryThreadChangePriorityWindow(mThreadsList[this->mThreads.GetCursor()].ThreadIdentifier, current, CrySearchIml::ChangePrioritySmall()).Execute();
	
	this->LoadThreads();
}

void CryThreadWindow::SuspendThread()
{
	if (!CrySuspendThread(mMemoryScanner->GetHandle(), mThreadsList[this->mThreads.GetCursor()].ThreadIdentifier))
	{
		Prompt("Thread Error", CtrlImg::error(), "Failed to suspend the selected thread.", "OK");
	}
	
	// Refresh the thread list to review the suspended thread.
	this->LoadThreads();
}

void CryThreadWindow::ResumeThread()
{
	if (CryResumeThread(mThreadsList[this->mThreads.GetCursor()].ThreadIdentifier) == -1)
	{
		Prompt("Thread Error", CtrlImg::error(), "Failed to resume the selected thread.", "OK");
	}
	
	// Refresh the thread list to review the suspended thread.
	this->LoadThreads();
}

void CryThreadWindow::TerminateThread()
{
	if (!Prompt("Are you sure?", CtrlImg::question(), "Are you sure you want to attempt termination of the selected thread?", "Yes", "No"))
	{
		return;
	}
	
	if (CryTerminateThread(mThreadsList[this->mThreads.GetCursor()].ThreadIdentifier) == -1)
	{
		Prompt("Thread Error", CtrlImg::error(), "Failed to terminate the selected thread.", "OK");
	}
	
	this->LoadThreads();
}

void CryThreadWindow::ShowThreadInformationWindow()
{
	CryThreadInformationBlockWindow* ctibw = new CryThreadInformationBlockWindow(mThreadsList[this->mThreads.GetCursor()].ThreadIdentifier);
	ctibw->Execute();
	delete ctibw;
}

void CryThreadWindow::SnapContextButtonClicked()
{
	CryThreadContextSnapWindow* ctcsw = new CryThreadContextSnapWindow(CrySearchIml::SnapContextSmall(), mThreadsList[this->mThreads.GetCursor()].ThreadIdentifier);
	ctcsw->Execute();
	delete ctcsw;
}