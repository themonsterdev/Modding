#include "stdafx.h"
#include "Pattern.h"

uintptr_t Pattern::m_begin	= 0;
uintptr_t Pattern::m_end	= 0;
uint32_t Pattern::m_size	= 0;

void Pattern::InitBaseAddress(HMODULE hModuleGtaV)
{
	const IMAGE_DOS_HEADER* dosHeader	= reinterpret_cast<const IMAGE_DOS_HEADER*>(hModuleGtaV);
	const IMAGE_NT_HEADERS* ntHeader	= reinterpret_cast<const IMAGE_NT_HEADERS64*>(
		reinterpret_cast<const uint8_t*>(dosHeader) + dosHeader->e_lfanew
	);

	m_begin = reinterpret_cast<uintptr_t>(hModuleGtaV);
	m_end	= m_begin + ntHeader->OptionalHeader.SizeOfCode;
	m_size	= ntHeader->OptionalHeader.SizeOfImage;

	LOGGER_DEBUG("baseAddr\t\t   0x%p   llu   0x%llu", m_begin, m_begin);
	LOGGER_DEBUG("endAddr\t\t    0x%p   llu   0x%llu", m_begin + m_size, m_begin + m_size);
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
