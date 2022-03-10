#include "stdafx.h"

static NativeManagerContext g_context;
static UINT64				g_hash;

scrNativeCallContext::SetVectorResults scrNativeCallContext::m_fpSetVectorResults = nullptr;

void nativeInit(UINT64 hash)
{
	g_context.Reset();
	g_hash = hash;
}

void nativePush64(UINT64 value)
{
	g_context.Push(value);
}

uint64_t* nativeCall()
{
	auto fnHandler = ScriptEngine::GetNativeHandler(g_hash);

	if (fnHandler != 0)
	{
		static void* exceptionAddress;

		__try
		{
			fnHandler(&g_context);
			scrNativeCallContext::m_fpSetVectorResults(&g_context);
		}
		__except (exceptionAddress = (GetExceptionInformation())->ExceptionRecord->ExceptionAddress, EXCEPTION_EXECUTE_HANDLER)
		{
			LOGGER_ERROR("executing native 0x%016llx at address %p.", g_hash, exceptionAddress);
		}
	}

	return reinterpret_cast<uint64_t*>(g_context.GetResultPointer());
}
