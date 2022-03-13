#include "pch.h"

Entry::Entry(char* name)
	: m_processName	(name)
	, m_processId	(0)
	, m_baseAddress	(nullptr)
	, m_baseSize	(0)
{}

// Process Id

DWORD Entry::GetProcessId(DWORD th32ProcessID)
{
	if (m_processId == 0)
	{
		PROCESSENTRY32 pe32{ 0 };

		// Take a snapshot of all processes in the system.
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, th32ProcessID);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			LOGGER_ERROR("CreateToolhelp32Snapshot (of processes)");
			return 0;
		}

		// Set the size of the structure before using it.
		pe32.dwSize = sizeof(PROCESSENTRY32);

		// Retrieve information about the first process
		if (Process32First(hProcessSnap, &pe32) == 0)
		{
			LOGGER_ERROR("Failed to gather information on system processes!");	// show cause of failure
			CloseHandle(hProcessSnap);											// clean the snapshot object
			return 0;
		}

		// Now walk the snapshot of processes
		do
		{
			if (strcmp(m_processName, pe32.szExeFile) == 0)
			{
				m_processId = pe32.th32ProcessID; // this process

				// display information about each process in turn
				LOGGER_DEBUG("PROCESS NAME: %s", pe32.szExeFile);
				LOGGER_DEBUG("\t- Process ID        = 0x%08X", m_processId);
				LOGGER_DEBUG("\t- Module ID         = 0x%08X", pe32.th32ModuleID);
				LOGGER_DEBUG("\t- Thread count      = %d", pe32.cntThreads);
				LOGGER_DEBUG("\t- Parent process ID = 0x%08X", pe32.th32ParentProcessID);
				LOGGER_DEBUG("\t- Priority base     = %d", pe32.pcPriClassBase);
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32));

		if (m_processId == 0)
			LOGGER_ERROR("Unable to find Process ID");

		CloseHandle(hProcessSnap);
	}

	return m_processId;
}

// Base
LPBYTE Entry::GetBaseAddress(DWORD th32ProcessID)
{
	if (m_baseAddress == nullptr)
	{
		MODULEENTRY32 me32{ 0 };

		// Take a snapshot of all modules in the specified process.
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, th32ProcessID);
		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			LOGGER_ERROR("CreateToolhelp32Snapshot (of modules)");
			return nullptr;
		}

		// Set the size of the structure before using it.
		me32.dwSize = sizeof(MODULEENTRY32);

		// Retrieve information about the first module.
		if (Module32First(hModuleSnap, &me32) == 0)
		{
			LOGGER_ERROR("Failed to gather information on system modules");	// show cause of failure
			CloseHandle(hModuleSnap);										// Must clean up the snapshot object!
			return nullptr;
		}

		//  Now walk the module list of the process.
		do
		{
			if (strcmp(m_processName, me32.szModule) == 0)
			{
				m_baseAddress	= me32.modBaseAddr;
				m_baseSize		= me32.modBaseSize;

				// display information about each module
				LOGGER_DEBUG("MODULE NAME: %s", me32.szModule);
				LOGGER_DEBUG("\t- Executable    = %s", me32.szExePath);
				LOGGER_DEBUG("\t- Process ID    = 0x%08X", me32.th32ProcessID);
				LOGGER_DEBUG("\t- Base address  = 0x%p", m_baseAddress);
				LOGGER_DEBUG("\t- Base size     = %d", m_baseSize);
				break;
			}
		} while (Module32Next(hModuleSnap, &me32));

		if (m_baseAddress == nullptr)
			LOGGER_ERROR("Unable to find module base address ID");

		// Do not forget to clean up the snapshot object. 
		CloseHandle(hModuleSnap);
	}

	return m_baseAddress;
}

DWORD Entry::GetBaseSize()
{
	return m_baseSize;
}
