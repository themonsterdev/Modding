#include "stdafx.h"

Process::Process(const char* processName)
	: m_processName(processName)
	, m_dProcessId(0)
{}

DWORD Process::GetProcessId()
{
	PROCESSENTRY32 pe32 { 0 };
	DWORD result = 0;

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
		LOGGER_ERROR("Failed to gather information on system processes!"); // show cause of failure
		CloseHandle(hProcessSnap);									// clean the snapshot object
		return 0;
	}

	// Now walk the snapshot of processes
	do
	{
		if (strcmp(m_processName, pe32.szExeFile) == 0)
		{
			result = pe32.th32ProcessID; // this process

			// display information about each process in turn
			LOGGER_DEBUG("PROCESS NAME: %s", pe32.szExeFile);
			LOGGER_DEBUG("\t- Process ID        = 0x%08X", result);
			LOGGER_DEBUG("\t- Module ID         = 0x%08X", pe32.th32ModuleID);
			LOGGER_DEBUG("\t- Thread count      = %d", pe32.cntThreads);
			LOGGER_DEBUG("\t- Parent process ID = 0x%08X", pe32.th32ParentProcessID);
			LOGGER_DEBUG("\t- Priority base     = %d", pe32.pcPriClassBase);
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	if (result == 0)
		LOGGER_ERROR("Unable to find Process ID");

	CloseHandle(hProcessSnap);
	return result;
}

LPBYTE Process::GetModuleBaseAddress(DWORD processId)
{
	MODULEENTRY32 me32{ 0 };
	LPBYTE result = nullptr;

	// Take a snapshot of all modules in the specified process.
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
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
			result = me32.modBaseAddr;

			// display information about each module
			LOGGER_DEBUG("[+]MODULE NAME: %s", me32.szModule);
			LOGGER_DEBUG("\t- Executable    = %s", me32.szExePath);
			LOGGER_DEBUG("\t- Process ID    = 0x%08X", me32.th32ProcessID);
			LOGGER_DEBUG("\t- Ref count (g) = 0x%04X", me32.GlblcntUsage);
			LOGGER_DEBUG("\t- Ref count (p) = 0x%04X", me32.ProccntUsage);
			LOGGER_DEBUG("\t- Base address  = 0x%p", result);
			LOGGER_DEBUG("\t- Base size     = %d", me32.modBaseSize);
			break;
		}
	} while (Module32Next(hModuleSnap, &me32));

	if (result == nullptr)
		LOGGER_ERROR("Unable to find module base address ID");

	// Do not forget to clean up the snapshot object. 
	CloseHandle(hModuleSnap);

	return result;
}

BOOL Process::InjectModule(const int& processId, const string& dllFilepath)
{
	size_t dll_size = dllFilepath.length() + 1;

	// OpenProcess
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProc == NULL)
	{
		LOGGER_ERROR("Fail to open target process");
		return false;
	}
	LOGGER_DEBUG("Opening Target Process...");

	// VirtualAllocEx
	LPVOID MyAlloc = VirtualAllocEx(hProc, 0, dll_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (MyAlloc == NULL)
	{
		LOGGER_ERROR("Fail to allocate memory in Target Process.");
		return false;
	}
	LOGGER_DEBUG("Allocating memory in Target Process.");

	// VirtualProtectEx
	DWORD dwProtOut = 0;
	if (!VirtualProtectEx(hProc, MyAlloc, dll_size, PAGE_EXECUTE_READWRITE, &dwProtOut))
	{
		LOGGER_ERROR("Failed to set permissions on loader.");
		return false;
	}

	// WriteProcessMemory
	if (!WriteProcessMemory(hProc, MyAlloc, dllFilepath.c_str(), dll_size, 0))
	{
		LOGGER_ERROR("Fail to write in Target Process memory.");
		return false;
	}
	LOGGER_DEBUG("Creating Remote Thread in Target Process.");

	// Reset VirtualProtectEx
	if (!VirtualProtectEx(hProc, MyAlloc, dll_size, dwProtOut, &dwProtOut))
	{
		LOGGER_ERROR("Failed to reset permissions on loader.");
		return false;
	}

	// GetProcAddress
	HMODULE hModuleKernel32 = LoadLibrary("kernel32");
	if (hModuleKernel32 == 0)
	{
		LOGGER_ERROR("Failed to set permissions on loader");
		return false;
	}
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
		hModuleKernel32,
		"LoadLibraryA"
	);

	// CreateRemoteThread
	DWORD dWord;
	HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
	if (ThreadReturn == NULL)
	{
		LOGGER_ERROR("Fail to create Remote Thread.");
		return false;
	}

	WaitForSingleObject(ThreadReturn, INFINITE);
	CloseHandle(ThreadReturn);
	return true;
}
