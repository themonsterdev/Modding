#include "stdafx.h"

static unordered_map<uint64_t, NativeHandler> g_handlerCache;

NativeRegistration** ScriptEngine::m_registrationTable = nullptr;

NativeHandler ScriptEngine::GetNativeHandler(uint64_t oldHash)
{
	auto& handler = g_handlerCache[oldHash];
	if (handler == nullptr)
	{
		uint64_t newHash = CrossMapping::MapNative(oldHash);
		if (newHash == 0)
		{
			LOGGER_DEBUG("Failed to GetNewHashFromOldHash(%llX)", oldHash);
			return nullptr;
		}

		NativeRegistration* table = m_registrationTable[newHash & 0xFF];

		for (; table; table = table->getNextRegistration())
		{
			for (uint32_t i = 0; i < table->getNumEntries(); i++)
			{
				if (newHash == table->getHash(i))
				{
					return table->handlers[i];
				}
			}
		}

		return nullptr;
	}

	return handler;
}
