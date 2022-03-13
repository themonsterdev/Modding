#include "stdafx.h"

uintptr_t Pattern::m_begin	= 0;
uintptr_t Pattern::m_end	= 0;
uint32_t Pattern::m_size	= 0;

void Pattern::InitBaseAddress(HMODULE hModule)
{
	const IMAGE_DOS_HEADER* dosHeader	= reinterpret_cast<const IMAGE_DOS_HEADER*>(hModule);
	const IMAGE_NT_HEADERS* ntHeader	= reinterpret_cast<const IMAGE_NT_HEADERS64*>(
		reinterpret_cast<const uint8_t*>(dosHeader) + dosHeader->e_lfanew
	);

	m_begin = reinterpret_cast<uintptr_t>(hModule);
	m_end	= m_begin + ntHeader->OptionalHeader.SizeOfCode;
	m_size	= ntHeader->OptionalHeader.SizeOfImage;

	//char filename[MAX_PATH];
	//GetModuleFileName(hModule, filename, MAX_PATH);
	//LOGGER_DEBUG("- filename %s", filename);

	//Entry process(filename);
	//DWORD processId		= process.GetProcessId(0);
	//LPBYTE baseAddress	= process.GetBaseAddress(processId);
	//DWORD baseSize		= process.GetBaseSize();
	//LOGGER_DEBUG("%p", baseAddress);
	//LOGGER_DEBUG("%d", baseSize);
}

bool Pattern::CompareMemory(const uint8_t* pData, const uint8_t* bMask, const char* sMask)
{
	for (; *sMask; ++sMask, ++pData, ++bMask)
	{
		if (*sMask == 'x' && *pData != *bMask)
		{
			return false;
		}
	}

	return *sMask == NULL;
}
