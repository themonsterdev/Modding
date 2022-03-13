#include "stdafx.h"

static NativeManagerContext s_context;
static UINT64				s_hash;

NativeRegistration** s_registrationTable	= nullptr;
SetVectorResults s_setVectorResults			= nullptr;

void nativeInit(UINT64 hash)
{
	s_context.Reset();
	s_hash = hash;
}
void nativePush64(UINT64 value)
{
	s_context.Push(value);
}
uint64_t* nativeCall()
{
	auto fnHandler = GetNativeHandler(s_hash);

	if (fnHandler != 0)
	{
		static void* exceptionAddress;

		__try
		{
			fnHandler(&s_context);
			s_setVectorResults(&s_context);
		}
		__except (exceptionAddress = (GetExceptionInformation())->ExceptionRecord->ExceptionAddress, EXCEPTION_EXECUTE_HANDLER)
		{
			LOGGER_ERROR("executing native 0x%016llx at address %p.", s_hash, exceptionAddress);
		}
	}

	return reinterpret_cast<uint64_t*>(s_context.GetResultPointer());
}

static unordered_map<uint64_t, NativeHandler> s_handlerCache;
NativeHandler GetNativeHandler(uint64_t oldHash)
{
	auto& handler = s_handlerCache[oldHash];
	if (handler == nullptr)
	{
		uint64_t newHash = CrossMapping::MapNative(oldHash);
		if (newHash == 0)
		{
			LOGGER_DEBUG("Failed to GetNewHashFromOldHash(%llX)", oldHash);
			return nullptr;
		}

		NativeRegistration* table = s_registrationTable[newHash & 0xFF];

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
