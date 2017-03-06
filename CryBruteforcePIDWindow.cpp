#include "CryBruteforcePIDWindow.h"
#include "BackendGlobalDef.h"
#include "ImlProvider.h"

#define BRUTE_FORCE_WORD	0
#define BRUTE_FORCE_DWORD	1

// CryBruteforcePIDWindow default constructor.
CryBruteforcePIDWindow::CryBruteforcePIDWindow() : CryDialogTemplate(CrySearchIml::BruteForceSmall())
{
	this->Title("Brute-Force PID").Sizeable().SetRect(0, 0, 600, 300);
	
	this->mClose <<= THISBACK(CloseWindow);
	this->mBegin <<= THISBACK(BruteForceBegin);
	
	this->mPidResults.AddColumn("PID", 15);
	this->mPidResults.AddColumn("Path", 65);
	this->mPidResults.AddColumn("Architecture", 20);
	
	*this
		<< this->mPidResultCount.SetLabel("Select Brute-Force length and click Begin").HSizePos(5, 5).TopPos(5, 25)
		<< this->mPidResults.HSizePos(5, 5).VSizePos(35, 35)
		<< this->mOptionsSelector.Add("WORD (16-bit)").Add("DWORD (32-bit)").LeftPos(5, 200).BottomPos(5, 25)
		<< this->mBegin.SetLabel("Begin").LeftPos(210, 70).BottomPos(5, 25)
		<< this->mBruteForceProgress.LeftPos(285, 100).BottomPos(5, 25)
		<< this->mClose.SetLabel("Close").RightPos(5, 70).BottomPos(5, 25)
	;
	
	this->mOptionsSelector.SetIndex(0);
}

// CryBruteforcePIDWindow default destructor.
CryBruteforcePIDWindow::~CryBruteforcePIDWindow()
{
	
}

// ---------------------------------------------------------------------------------------------

// Closes the window.
void CryBruteforcePIDWindow::CloseWindow()
{
	this->Close();
}

// Begins brute-forcing PIDs, either 16 or 32 bits.
void CryBruteforcePIDWindow::BruteForceBegin()
{
	// Reset results and progress indicator.
	this->mBruteForceProgress.Set(0, 100);
	this->mPidResults.Clear();
	this->mPidResultCount.SetLabel("Running...");
	
	unsigned long numIterations = 0;
	
	// Brute-Force 16 or 32 bit?
	switch (this->mOptionsSelector.GetIndex())
	{
		case BRUTE_FORCE_WORD:
			numIterations = USHRT_MAX;
			break;
		case BRUTE_FORCE_DWORD:
			numIterations = UINT_MAX;
			break;
	}
	
	// Split the brute-forcing work into multiple threads.
	const int threadCount = mMemoryScanner->GetSystemThreadCount();
	const int threadWork = numIterations / threadCount;
	const int threadWorkRemainder = numIterations % threadCount;
	for (int i = 0; i < threadCount; ++i)
	{
		// Append the remainder of unprecise division to the first worker.
		unsigned long start = threadWork * i;
		if (!i)
		{
			start += threadWorkRemainder;
		}
		
		// Schedule a worker.
		//this->mBruteForceResultList.Add(i);
		//this->mThreadPool & THISBACK3(BruteForceWorker, i, start, threadWork);
	}
}

// Worker report callback.
/*void CryBruteforcePIDWindow::WorkerReportProcessFound(const Vector<BasicOpenProcessInfo>& intermediate)
{
	//PostCallback(THISBACK1(WorkerReportProcessFoundThreadSafe, intermediate));
}

// Thread safe variant of worker report callback. This function may alter UI components.
void CryBruteforcePIDWindow::WorkerReportProcessFoundThreadSafe(const Vector<BasicOpenProcessInfo>& intermediate)
{
	// Append the local results of the worker in case to the global.
	
}*/

// Peeks whether the disassembly work has completed, i.e. all workers have finished their work.
/*const bool CryBruteforcePIDWindow::PeekIsFinished() const
{
	// Walk the currently running workers.
	for (auto const& info : this->mBruteForceResultList)
	{
		// Check whether the current worker has completed.
		if (!info.HasFinished)
		{
			// A worker is not yet finished.
			return false;
		}
	}
	
	// All workers have completed their work.
	return true;
}*/

// Executes actual brute-forcing work.
void CryBruteforcePIDWindow::BruteForceWorker(const int id, const unsigned long begin, const unsigned long count)
{
	// Execute the Brute-Force operation.
	int numFound = 0;
	//Vector<BasicOpenProcessInfo>& local = this->mBruteForceResultList.Get(id);
	for (unsigned long i = begin; i < count; ++i)
	{
		// Query the process ID.
		BasicOpenProcessInfo procInfo;
		if (QueryOpenProcessBasic(i, &procInfo))
		{
			// We found a PID that we could open!Add the process to the local list of results.
			++numFound;
			//local << procInfo;
			
			//this->mPidResults.Add(procInfo.ProcessID, WString(procInfo.ProcessPath), procInfo.Is32 ? "32-bit" : "64-bit");
		}
	}
	
	// Update the progress indicator.
	//this->WorkerReportProcessFound(local);
}

// Sets the result label to whatever number of results there currently are.
void CryBruteforcePIDWindow::SetResultLabel(const int numres)
{
	this->mPidResultCount.SetLabel(Format("Brute-Force found %i Process ID's", numres));
}