// Hooking.cpp
#pragma once

#include "stdafx.h"

static HANDLE mainFiber = nullptr;
static DWORD wakeAt		= 0;

typedef BOOL(WINAPIV*IS_DLC_PRESENT)(uint32_t);

static IS_DLC_PRESENT	is_DLC_present;
IS_DLC_PRESENT			fpIsDLCPresent = nullptr;

// NativeHandler

// Native function handler type
struct NativeRegistrationNew
{
	uint64_t		nextRegistration1;
	uint64_t		nextRegistration2;
	NativeHandler	handlers[7];
	uint32_t		numEntries1;
	uint32_t		numEntries2;
	uint64_t		hashes;

	inline NativeRegistrationNew* getNextRegistration()
	{
		uintptr_t result;
		auto v5 = reinterpret_cast<uintptr_t>(&nextRegistration1);
		auto v12 = 2i64;
		auto v13 = v5 ^ nextRegistration2;
		auto v14 = (char*)&result - v5;
		do
		{
			*(DWORD*)&v14[v5] = (DWORD)(v13 ^ *(DWORD*)v5);
			v5 += 4i64;
			--v12;
		} while (v12);

		return reinterpret_cast<NativeRegistrationNew*>(result);
	}

	inline uint32_t getNumEntries()
	{
		return ((uint32_t)((uintptr_t)&numEntries1)) ^ numEntries1 ^ numEntries2;
	}

	inline uint64_t getHash(uint32_t index)
	{
		auto naddr = 16 * index + reinterpret_cast<uintptr_t>(&nextRegistration1) + 0x54;
		auto v8 = 2i64;
		uint64_t nResult;
		auto v11 = (char*)&nResult - naddr;
		auto v10 = naddr ^ *(DWORD*)(naddr + 8);
		do
		{
			*(DWORD*)&v11[naddr] = (DWORD)(v10 ^ *(DWORD*)(naddr));
			naddr += 4i64;
			--v8;
		} while (v8);

		return nResult;
	}
};

static NativeRegistrationNew**					m_registrationTable;
static unordered_map<uint64_t, NativeHandler>	m_handlerCache;

// typedef void(__cdecl* NativeHandler)(scrNativeCallContext* context);
NativeHandler Hooking::GetNativeHandler(uint64_t origHash)
{
	auto& handler = m_handlerCache[origHash];

	if (handler == nullptr)
	{
		uint64_t newHash = CrossMapping::MapNative(origHash);
		if (newHash == 0)
		{
			return nullptr;
		}

		NativeRegistrationNew* table = m_registrationTable[newHash & 0xFF];

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

// Fiber

void __stdcall ScriptFunction(LPVOID lpParameter)
{
	try
	{
		ScriptMain();
	}
	catch (...)
	{
		Log::Fatal("Failed scriptFiber");
	}
}
void Hooking::onTickInit()
{
	if (mainFiber == nullptr)
		mainFiber = ConvertThreadToFiber(nullptr);

	if (mainFiber == nullptr)
		mainFiber = GetCurrentFiber();

	if (timeGetTime() < wakeAt)
		return;

	static HANDLE scriptFiber = 0;
	if (scriptFiber == 0)
		scriptFiber = CreateFiber(0, ScriptFunction, nullptr);
	else
		SwitchToFiber(scriptFiber);
}
void WAIT(DWORD ms)
{
	wakeAt = timeGetTime() + ms;
	SwitchToFiber(mainFiber);
}

// Patterns

static void FindIsDLCPresent()
{
	DEBUGMSG("  ---->  Getting hooks...\n");

	// 48 89 5C 24 ?? 57 48 83 EC 20 81 F9 ?? ?? ?? ??
	is_DLC_present = Pattern::FindPattern<IS_DLC_PRESENT>(
		"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x20\x81\xF9\x00\x00\x00\x00",
		"xxxx?xxxxxxx????"
	);
	DEBUGMSG("FindPattern Hooking::m_fpIsDLCPresentTarget     0x%p   llu  %llu", is_DLC_present, is_DLC_present);
	DEBUGMSG("==============================================================================================================");
}
static void FindFixVectors()
{
	DEBUGMSG("  ---->  Getting vector3 result fixer func...\n");

	scrNativeCallContext::m_fpSetVectorResults = Pattern::FindPattern<scrNativeCallContext::SetVectorResults>(
		"\x83\x79\x18\x00\x48\x8B\xD1\x74\x4A\xFF\x4A\x18\x48\x63\x4A\x18\x48\x8D\x41\x04\x48\x8B\x4C\xCA",
		"xxx?xxxxxxxxxxxxxxxxxxxx"
	);
	DEBUGMSG("FindPattern Hooking::m_fpSetVectorsResults     0x%p   llu  %llu", scrNativeCallContext::m_fpSetVectorResults, scrNativeCallContext::m_fpSetVectorResults);
	DEBUGMSG("==============================================================================================================");
}
static void FindNatives()
{
	DEBUGMSG("  ---->  Getting native registration table...\n");

	char* address = Pattern::FindPattern<char*>(
		"\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\x14\xFA\xE8\x00\x00\x00\x00\x48\x85\xC0\x75\x0A",
		"xx?????xxxxx????xxxxx"
	);

	char* location = reinterpret_cast<char*>(address + 3);
	DEBUGMSG("location 0x%p llu 0x%llu", location, *location);

	m_registrationTable = reinterpret_cast<NativeRegistrationNew**>(
		location + *(int32_t*)location + 4
	);
	DEBUGMSG("NativeTable 0x%p llu 0x%llu", m_registrationTable, m_registrationTable);
	DEBUGMSG("======================================================\n");

	DEBUGMSG("Initializing Native Map...");
	CrossMapping::InitNativeMap();
	DEBUGMSG("Native Map Initialized OK\n");
}
void Hooking::FindPatterns(HMODULE hModuleDll)
{
	// GetModuleHandle(NULL) -> C:\Program Files\Epic Games\GTAV\GTA5.exe
	// hModule				 -> C:\Users\themo\Downloads\Menu_Base\x64\Debug\Menu_Base_DLL.dll

	HMODULE hModuleHandleGtaV = GetModuleHandle(NULL);
	Pattern::InitBaseAddress(hModuleHandleGtaV);

	char fileNameA[MAX_PATH];
	char fileNameB[MAX_PATH];
	GetModuleFileNameA(hModuleHandleGtaV, fileNameA, MAX_PATH);
	GetModuleFileNameA(hModuleDll, fileNameB, MAX_PATH);

	DEBUGMSG("%s\t\t   0x%p   llu   0x%llu", fileNameA, hModuleHandleGtaV, hModuleHandleGtaV);
	DEBUGMSG("%s\t\t   0x%p   llu   0x%llu", fileNameB, hModuleDll,		   hModuleDll);

	FindIsDLCPresent();
	FindFixVectors();
	FindNatives();
}

// Hooks

// Detour function which overrides IS_DLC_PRESENT.
BOOL WINAPIV HK_IS_DLC_PRESENT(uint32_t dlcHash)
{
	static int frameCount = 0;
	int newFrameCount = GAMEPLAY::GET_FRAME_COUNT();

	if (newFrameCount > frameCount)
	{
		frameCount = newFrameCount;

		Hooking::onTickInit();
	}

	if (dlcHash == 0x96F02EE6)
		return true;

	return fpIsDLCPresent(dlcHash);
}
bool Hooking::HookNatives()
{
	// Create a hook for IS_DLC_PRESENT, in disabled state.
	MH_STATUS status = MH_CreateHook(
		is_DLC_present,
		HK_IS_DLC_PRESENT,
		reinterpret_cast<LPVOID*>(&fpIsDLCPresent)
	);
	if (status != MH_STATUS::MH_OK && status != MH_STATUS::MH_ERROR_ALREADY_CREATED)
	{
		Log::Error("Failed to MH_CreateHook : %s", MH_StatusToString(status));
		return false;
	}
	DEBUGMSG("MH_CreateHook : OK");

	// Enable the hook for IS_DLC_PRESENT.
	status = MH_EnableHook(is_DLC_present);
	if (status != MH_STATUS::MH_OK)
	{
		Log::Error("Failed to MH_EnableHook : %s", MH_StatusToString(status));
		return false;
	}
	DEBUGMSG("MH_CreateHook : OK");

	return true;
}
BOOL Hooking::InitializeHooks()
{
	BOOL returnVal = TRUE;

	// MH_Initialize
	MH_STATUS status = MH_Initialize();
	if (status == MH_STATUS::MH_OK)
		DEBUGMSG("MH_Initialize Initialized OK");
	else
	{
		Log::Error("Failed to MH_Initialize : %s", MH_StatusToString(status));

		returnVal = FALSE;
	}

	// HookNatives
	if (HookNatives())
		DEBUGMSG("HookNatives Initialized OK");
	else
	{
		Log::Error("Failed to initialize NativeHooks");
		returnVal = FALSE;
	}

	return returnVal;
}

// Start/Stop

void Hooking::Start(HMODULE hModule)
{
	DisableThreadLibraryCalls(hModule);

	DEBUGMSG("Start hooks");
	Log::Init(hModule);

	// Init Patterns/Hooks
	FindPatterns(hModule);
	InitializeHooks();
}
void Hooking::Stop()
{
	// Disable the hook for IS_DLC_PRESENT.
	MH_STATUS status = MH_DisableHook(is_DLC_present);
	if (status != MH_STATUS::MH_OK)
	{
		Log::Error("Failed to MH_DisableHook :%s\n", MH_StatusToString(status));
		return;
	}
	DEBUGMSG("MH_DisableHook : OK");

	// Remove the hook for IS_DLC_PRESENT.
	status = MH_RemoveHook(is_DLC_present);
	if (status != MH_STATUS::MH_OK)
	{
		Log::Error("Failed to MH_RemoveHook :%s\n", MH_StatusToString(status));
		return;
	}
	DEBUGMSG("MH_RemoveHook : OK");

	// Uninitialize MinHook.
	status = MH_Uninitialize();
	if (status != MH_STATUS::MH_OK)
		Log::Error("Failed to MH_Uninitialize :%s\n", MH_StatusToString(status));
}
