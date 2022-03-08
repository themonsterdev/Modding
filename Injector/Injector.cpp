// Injector.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//


#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>

#include <iostream>
#include <string>

#include <Shlwapi.h>

//Library needed by Linker to check file existance
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
class Process
{
public:

	Process(const char* processName);

	DWORD GetProcessId();

	BOOL ReadProcessMemory(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize
	);

	BOOL WriteProcessMemory(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize
	);

private:

	const char* m_processName;
	DWORD m_dProcessId;
};

Process::Process(const char* processName)
	: m_processName	(processName)
	, m_dProcessId	(0)
{}

DWORD Process::GetProcessId()
{
	PROCESSENTRY32 pe32{ 0 };
	DWORD result = 0;

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

	// Retrieve information about the first process
	if (Process32First(hProcessSnapshot, &pe32) == 0)
	{
		CloseHandle(hProcessSnapshot); // clean the snapshot object
		printf("Failed to gather information on system processes! \n");

		// exit if unsuccessful
		return 0;
	}

	do
	{
		// printf("Checking process %ls\n", pe32.szExeFile);

		if (strcmp(m_processName, pe32.szExeFile) == 0)
		{
			result = pe32.th32ProcessID;

			printf("[+]Found %s\n", pe32.szExeFile);
			printf("[+]Process ID: %u.\n", result);
			break;
		}
	} while (Process32Next(hProcessSnapshot, &pe32));

	if (result == 0)
		printf("[!]Unable to find Process ID\n");

	CloseHandle(hProcessSnapshot);
	return result;
}

BOOL Process::ReadProcessMemory(
	HANDLE hProcess,
	LPCVOID lpBaseAddress,
	LPVOID lpBuffer,
	SIZE_T nSize
) {
	SIZE_T lpNumberOfBytesRead;
	return ::ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesRead) && lpNumberOfBytesRead > 0;
}

BOOL Process::WriteProcessMemory(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize
) {
	return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize);
}

BOOL InjectDll(const int& processId, const string& dllFilepath)
{
	size_t dll_size = dllFilepath.length() + 1;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	if (hProc == NULL)
	{
		cerr << "[!]Fail to open target process!" << endl;
		return false;
	}
	cout << "[+]Opening Target Process..." << endl;

	LPVOID MyAlloc = VirtualAllocEx(hProc, 0, dll_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (MyAlloc == NULL)
	{
		cerr << "[!]Fail to allocate memory in Target Process." << endl;
		return false;
	}

	cout << "[+]Allocating memory in Target Process." << endl;
	int IsWriteOK = WriteProcessMemory(hProc, MyAlloc, dllFilepath.c_str(), dll_size, 0);
	if (IsWriteOK == 0)
	{
		cerr << "[!]Fail to write in Target Process memory." << endl;
		return false;
	}
	cout << "[+]Creating Remote Thread in Target Process" << endl;

	//set execute permission
	DWORD dwProtOut = 0;
	if (!VirtualProtectEx(hProc, MyAlloc, dll_size, PAGE_EXECUTE_READWRITE, &dwProtOut))
	{
		printf("Failed to set permissions on loader\n");
		return false;
	}

	DWORD dWord;
	HMODULE hModuleKernel32 = LoadLibrary("kernel32");
	if (hModuleKernel32 == 0)
	{
		printf("Failed to set permissions on loader\n");
		return false;
	}
	LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
		hModuleKernel32,
		"LoadLibraryA"
	);
	HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
	if (ThreadReturn == NULL)
	{
		cerr << "[!]Fail to create Remote Thread" << endl;
		return false;
	}

	if ((hProc != NULL) && (MyAlloc != NULL) && (IsWriteOK != ERROR_INVALID_HANDLE) && (ThreadReturn != NULL))
	{
		cout << "[+]DLL Successfully Injected :)" << endl;
		WaitForSingleObject(ThreadReturn, INFINITE);
		CloseHandle(ThreadReturn);
		return true;
	}

	return false;
}

char* GetDllFilepath(string arg0, const char* dllFilename)
{
	static char dllFilepath[MAX_PATH];
	strcpy_s(dllFilepath, arg0.substr(0, arg0.length() - 12).c_str());
	strcat_s(dllFilepath, dllFilename);

	printf("dllFilepath: %s.\n", dllFilepath);
	return dllFilepath;
}

// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory

VOID CopyProcessMemory(
	HANDLE hSrc, LPCVOID lpSrcBaseAddress,
	HANDLE hDest, LPVOID lpDestBaseAddress,
	SIZE_T nSize)
{
	CHAR lpBuffer[MAXCHAR] {};
	SIZE_T lpNumberOfBytesRead;

	BOOL success = ReadProcessMemory(hSrc, lpSrcBaseAddress, lpBuffer, nSize, &lpNumberOfBytesRead);
	if (success)
		return;

	success = WriteProcessMemory(hDest, lpDestBaseAddress, lpBuffer, nSize, &lpNumberOfBytesRead);
	if (success)
		return;
}

int main(int argc, char* argv[])
{
	shared_ptr<Process> gtavProcess = make_shared<Process>("GTA5.exe");
	DWORD processId					= gtavProcess->GetProcessId();
	printf("%d.\n", processId);
	return EXIT_SUCCESS;

	char* dllFilepath	= GetDllFilepath(argv[0], "MenuBase.dll");

	if (InjectDll(processId, dllFilepath) == 0)
	{
		printf("Failed to inject MenuBase.dll.\n");
		return EXIT_FAILURE;
	}

	printf("DLL MenuBase injected.\n");

	return EXIT_SUCCESS;
}
