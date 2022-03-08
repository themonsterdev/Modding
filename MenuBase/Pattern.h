#pragma once

class Pattern
{
public:

	static uintptr_t m_begin; // Base address
	static uintptr_t m_end;
	static uint32_t m_size;

	static void InitBaseAddress(HMODULE hModuleGtaV);

	static bool CompareMemory(const uint8_t* pData, const uint8_t* bMask, const char* sMask);

	template <typename T>
	static inline T FindPattern(const char* bMask, const char* sMask);
};

template <typename T>
inline T Pattern::FindPattern(const char* bMask, const char* sMask)
{
	uintptr_t address = 0;

	for (uint32_t offset = 0; offset < m_size; offset++)
	{
		address = m_begin + offset;

		if (CompareMemory((uint8_t*)address, (uint8_t*)bMask, sMask))
		{
			LOGGER_DEBUG("address p 0x%p llu %llu", address, address);
			return reinterpret_cast<T>(address);
		}
	}

	return nullptr;
}
