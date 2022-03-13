#include "stdafx.h"

static char* GetAbsoluteFilename(char* filepath, const char* filename)
{
	size_t slash = -1;
	for (size_t i = 0; i < strlen(filepath); i++)
	{
		if (filepath[i] == '/' || filepath[i] == '\\')
		{
			slash = i;
		}
	}

	if (slash != -1)
	{
		filepath[slash + 1] = '\0';

		static char buffer[MAX_PATH];
		strcpy_s(buffer, filepath);
		strcat_s(buffer, filename);
		return buffer;
	}

	return nullptr;
}

BOOL InjectModule(DWORD processId, const string& dllFilepath)
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
		LOGGER_ERROR("Failed to load module kernel32");
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

int main(int argc, char** argv)
{
	const char* injectorName = "Injector";

	// Logger
	const char* loggerPath = GetAbsoluteFilename(argv[0], injectorName);
	LOGGER_DEBUG("Logger path %s", loggerPath);
	Logger::Init(loggerPath);

	// Process
	Entry process(argv[1]);
	DWORD processId = process.GetProcessId(0);

	// Module
	process.GetBaseAddress(processId);
	const char* moduleFilename = GetAbsoluteFilename(argv[0], argv[2]);
	LOGGER_DEBUG("Module file path <%s> :).", moduleFilename);

	// Inject
	if (!InjectModule(processId, moduleFilename))
	{
		LOGGER_ERROR("Failed to inject <%s>.", moduleFilename);
		return EXIT_FAILURE;
	}

	LOGGER_DEBUG("Successfully Injected module <%s> :).", moduleFilename);
	return EXIT_SUCCESS;
}
