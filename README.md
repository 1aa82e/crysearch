# CrySearch Memory Scanner

Generic memory scanning, disassembling and process manipulation application for Windows.

## Getting to run it

To compile CrySearch and run it, you need the Ultimate++ Framework including IDE (TheIDE). You can download this software at http://www.ultimatepp.org/. Configure the IDE to run and copy the CrySearch source into an empty directory called *CrySearch*. Close/Reopen the IDE and select *CrySearch* from the **MyApps** library. Make sure the MSVC10(+) build method(s) are configured and build the project.

Open up Visual Studio and open the CrySearchLibrary project. Compile it for the architecture of CrySearch that you built using TheIDE.Copy the output dynamic link library into the CrySearch output folder. Copy BeaEngine(64).dll from the BeaEngine/lib folder to the output folder of CrySearch too. Run CrySearch. A default configuration file and empty plugin directory should be created. You can put plugins in this directory. Make sure you put them in the correct directory regarding the architecture of CrySearch.

## Author

evolution536

## Contribute

If you want to contribute to CrySearch, feel free to create a pull request. Every information available can be found at the UnknownCheats forum.

http://www.unknowncheats.me/forum/general-programming-and-reversing/100677-crysearch-memory-scanner.html