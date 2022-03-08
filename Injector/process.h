#pragma once

// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
class Process
{
public:

	Process(const char* processName);

	DWORD GetProcessId();
	LPBYTE GetModuleBaseAddress(DWORD processId);

	BOOL InjectModule(const int& processId, const string& dllFilepath);

private:

	const char* m_processName;
	DWORD m_dProcessId;

};
