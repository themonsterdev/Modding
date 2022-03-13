#pragma once

#include <string>

using namespace std;

// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
class Entry
{
public:

	Entry(char* name);

	// Process Id
	DWORD GetProcessId(DWORD th32ProcessID);

	// Base
	LPBYTE GetBaseAddress(DWORD th32ProcessID);
	DWORD GetBaseSize();

private:

	// Process Id
	const char*	m_processName;	// This process name
	DWORD		m_processId;	// This process id

	// Base address
	LPBYTE	m_baseAddress;	// Base address of module in th32ProcessID's context
	DWORD	m_baseSize;		// Size in bytes of module starting at modBaseAddr

};
