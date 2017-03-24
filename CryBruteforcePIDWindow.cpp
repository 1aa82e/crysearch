#include "CryBruteforcePIDWindow.h"
#include "BackendGlobalDef.h"
#include "ImlProvider.h"
#include "UIUtilities.h"
#include "CrySearchLibrary/SDK/ProcessCore.h"

// ---------------------------------------------------------------------------------------------

// Looks for a specific process in the specified process list.
const bool FindProcessIdInList(const int procID, const Vector<Win32ProcessInformation>& procList)
{
	for (auto const& proc : procList)
	{
		if (proc.ProcessId == procID)
		{
			// The process was found!
			return true;
		}
	}
	
	// The process was not found.
	return false;
}

// CryBruteforcePIDWindow default constructor.
CryBruteforcePIDWindow::CryBruteforcePIDWindow() : CryDialogTemplate(CrySearchIml::BruteForceSmall())
{
	this->Title("Brute-Force PID").Sizeable().SetRect(0, 0, 500, 300);
	
	this->mClose <<= THISBACK(CloseWindow);
	this->mBegin <<= THISBACK(BruteForceBegin);
	
	this->mPidResults.AddColumn("PID", 10);
	this->mPidResults.AddColumn("Path", 70);
	this->mPidResults.AddColumn("Architecture", 20);
	this->mPidResults.WhenBar = THISBACK(ProcessResultWhenBar);
	
	*this
		<< this->mPidResultCount.SetLabel("Click Begin to start Brute-Forcing").HSizePos(5, 5).TopPos(5, 25)
		<< this->mPidResults.HSizePos(5, 5).VSizePos(35, 35)
		<< this->mBegin.SetLabel("Begin").LeftPos(5, 70).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 70).BottomPos(5, 25)
	;
}

// CryBruteforcePIDWindow default destructor.
CryBruteforcePIDWindow::~CryBruteforcePIDWindow()
{
	
}

// ---------------------------------------------------------------------------------------------

// Populates the context menu bar for right-clicking the brute-force result list.
void CryBruteforcePIDWindow::ProcessResultWhenBar(Bar& pBar)
{
	const int row = this->mPidResults.GetCursor();
	if (row >= 0 && this->mPidResults.GetCount() > 0)
	{
		pBar.Add("Open Process", CrySearchIml::AttachToProcessMenu(), THISBACK(OpenBruteForcedProcess));
	}
}

// Opens a brute forced process.
void CryBruteforcePIDWindow::OpenBruteForcedProcess()
{
	const int row = this->mPidResults.GetCursor();
	this->tmpProc.ProcessId = this->mPidResults.Get(row, 0);
	this->AcceptBreak(10);
}

// Closes the window.
void CryBruteforcePIDWindow::CloseWindow()
{
	this->Close();
}

// Begins brute-forcing PIDs, either 16 or 32 bits.
void CryBruteforcePIDWindow::BruteForceBegin()
{
	// Reset results and progress indicator.
	this->mPidResults.Clear();
	this->mPidResultCount.SetLabel("Running...");
	
	// Now retrieve the regular process list, and see whether there are differences.
	Vector<Win32ProcessInformation> actualProcs;
	EnumerateProcesses(actualProcs);
	
	// Execute the Brute-Force operation.
	int rowCounter = -1;
	for (unsigned long i = 0; i < USHRT_MAX; ++i)
	{
		// Query the process ID.
		BasicOpenProcessInfo procInfo;
		if (QueryOpenProcessBasic(i, &procInfo))
		{
			// We found a PID that we could open!Add the process to the local list of results.
			this->mPidResults.Add(procInfo.ProcessID, WString(procInfo.ProcessPath), procInfo.Is32 ? "32-bit" : "64-bit");
			++rowCounter;
			
			// If this process ID is not in the list of regularly retrieved processes, we color the row.
			if (!FindProcessIdInList(i, actualProcs))
			{
				this->mPidResults.SetRowDisplay(rowCounter, RedDisplayDrawInstance);
			}
		}
	}
	
	// Update the user interface with the results.
	this->SetResultLabel(this->mPidResults.GetCount());
}

// Sets the result label to whatever number of results there currently are.
void CryBruteforcePIDWindow::SetResultLabel(const int numres)
{
	this->mPidResultCount.SetLabel(Format("Brute-Force found %i Process ID's (Marked red means not in regular process list)", numres));
}

// Retrieves the process that is currently selected.
Win32ProcessInformation* const CryBruteforcePIDWindow::GetSelectedProcess()
{
	return &this->tmpProc;
}