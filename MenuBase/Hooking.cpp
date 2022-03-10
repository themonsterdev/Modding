// Hooking.cpp
#include "stdafx.h"

static HANDLE mainFiber = nullptr;
static DWORD wakeAt		= 0;

typedef BOOL(WINAPIV*IS_DLC_PRESENT)(uint32_t); // length 8
static IS_DLC_PRESENT	fpIsDLCPresentTarget	= nullptr;
IS_DLC_PRESENT			fpIsDLCPresentOriginal	= nullptr;

// Patterns

void InitializeIsDLCPresent()
{
	LOGGER_DEBUG("----> Getting fpIsDLCPresentTarget...");

	/*
	76 32 48 8B 53 40 48 8D 0D 48 8D 0D + 4

	sub_7FF6900AA934+1F   028 76 32                                   jbe     short loc_7FF6900AA987 ; Jump if Below or Equal (CF=1 | ZF=1)
	sub_7FF6900AA934+21
	sub_7FF6900AA934+21                               loc_7FF6900AA955:                       ; CODE XREF: sub_7FF6900AA934+51↓j
	sub_7FF6900AA934+21   028 48 8B 53 40                             mov     rdx, [rbx+40h]
	sub_7FF6900AA934+25   028 48 8D 0D D0 3F 7D 01                    lea     rcx, unk_7FF69187E930 ; Load Effective Address
	*/

	/*
	sub_7FF68F54C674
	48 89 5C 24 ?? 57 48 83 EC 20 81 F9 ?? ?? ?? ??

	sub_7FF68F54C674      000 48 89 5C 24 08                          mov     [rsp+arg_0], rbx
	sub_7FF68F54C674+5    000 57                                      push    rdi
	sub_7FF68F54C674+6    008 48 83 EC 20                             sub     rsp, 20h        ; Integer Subtraction
	sub_7FF68F54C674+A    028 81 F9 6D 9F 11 0B                       cmp     ecx, 0B119F6Dh  ; Compare Two Operands
	sub_7FF68F54C674+10   028 75 08                                   jnz     short loc_7FF68F54C68E ; Jump if Not Zero (ZF=0)
	sub_7FF68F54C674+12   028 8A 05 19 78 B4 01                       mov     al, cs:byte_7FF691093EA5
	sub_7FF68F54C674+18   028 EB 6B                                   jmp     short loc_7FF68F54C6F9 ; Jump
	*/

	// 48 89 5C 24 ?? 57 48 83 EC 20 81 F9 ?? ?? ?? ??
	fpIsDLCPresentTarget = Pattern::FindPattern<IS_DLC_PRESENT>(
		"\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x20\x81\xF9\x00\x00\x00\x00",
		"xxxx?xxxxxxx????"
	);
	LOGGER_DEBUG("Pointeur 0x%p", fpIsDLCPresentTarget);
	LOGGER_DEBUG("Length 1 %u", sizeof fpIsDLCPresentTarget);
}
void InitializeFixVectors()
{
	LOGGER_DEBUG("----> Getting scrNativeCallContext::m_fpSetVectorResults...");

	// 83 79 18 ?? 48 8B D1 74 4A FF 4A 18 48 63 4A 18 48 8D 41 04 48 8B 4C CA
	// 
	//	sub_7FF6900A76B0        000 83 79 18 00                              cmp     dword ptr[rcx + 18h], 0; Compare Two Operands
	//	sub_7FF6900A76B0 + 4    000 48 8B D1                                 mov     rdx, rcx
	//	sub_7FF6900A76B0 + 7    000 74 4A                                    jz      short loc_7FF6900A7703; Jump if Zero(ZF = 1)
	//	sub_7FF6900A76B0 + 9
	//	sub_7FF6900A76B0 + 9                                 loc_7FF6900A76B9:; CODE XREF : sub_7FF6900A76B0 + 51↓j
	//	sub_7FF6900A76B0 + 9    000 FF 4A 18                                 dec     dword ptr[rdx + 18h]; Decrement by 1
	//	sub_7FF6900A76B0 + C    000 48 63 4A 18                              movsxd  rcx, dword ptr[rdx + 18h]; Move with Sign - Extend Doubleword
	//	sub_7FF6900A76B0 + 10   000 48 8D 41 04                              lea     rax, [rcx + 4]; Load Effective Address
	//	sub_7FF6900A76B0 + 14   000 48 8B 4C CA 20                           mov     rcx, [rdx + rcx * 8 + 20h]

	scrNativeCallContext::m_fpSetVectorResults = Pattern::FindPattern<scrNativeCallContext::SetVectorResults>(
		"\x83\x79\x18\x00\x48\x8B\xD1\x74\x4A\xFF\x4A\x18\x48\x63\x4A\x18\x48\x8D\x41\x04\x48\x8B\x4C\xCA",
		"xxx?xxxxxxxxxxxxxxxxxxxx"
	);
	LOGGER_DEBUG("Pointeur 0x%p", scrNativeCallContext::m_fpSetVectorResults);
}
void InitializeNatives()
{
	LOGGER_DEBUG("----> Getting ScriptEngine::m_registrationTable...");

	// 48 8D 0D ?? ?? ?? ?? 48 8B 14 FA E8 ?? ?? ?? ?? 48 85 C0 75 0A
	// 48 8D 0D D0 3F 7D 01 48 8B 14 FA E8 B3 04 48 FF 48 85 C0 75 0A -> 48 8D 05 FF F6 20 FF
	// 48 8D 0D D0 3F 7D 01 48 8B 14 FA E8 B3 04 48 FF 48 85 C0 75 0A -> 48 8D 05 FF F6 20 FF
	//
	//	sub_7FF6900AA934 + 21                                           loc_7FF6900AA955:                       ; CODE XREF: sub_7FF6900AA934+51↓j
	//	sub_7FF6900AA934 + 21   028 48 8B 53 40                                         mov     rdx, [rbx + 40h]
	//-	sub_7FF6900AA934 + 25   028 48 8D 0D D0 3F 7D 01                                lea     rcx, unk_7FF69187E930; Load Effective Address
	//-	sub_7FF6900AA934 + 2C   028 48 8B 14 FA                                         mov     rdx, [rdx + rdi * 8]
	//-	sub_7FF6900AA934 + 30   028 E8 B3 04 48 FF                                      call    sub_7FF68F52AE1C; Call Procedure
	//-	sub_7FF6900AA934 + 35   028 48 85 C0                                            test    rax, rax; Logical Compare
	//-	sub_7FF6900AA934 + 38   028 75 0A                                               jnz     short loc_7FF6900AA978; Jump if Not Zero(ZF = 0)
	//	sub_7FF6900AA934 + 3A   028 48 8D 05 FF F6 20 FF                                lea     rax, sub_7FF68F2BA074; Load Effective Address
	//	sub_7FF6900AA934 + 41   028 40 32 F6											xor sil, sil; Logical Exclusive OR

	//	address + 9
	//	76 32 48 8B 53 40 48 8D 0D
	//	0x00007FF68131A953
	//	char* address = Pattern::FindPattern<char*>(
	//		"\x76\x32\x48\x8B\x53\x40\x48\x8D\x0D",
	//		"xxxxxxxxx"
	//	);
	//
	// 0x00007FF68131A95C
	// char* location = reinterpret_cast<char*>(address + 9);
	// LOGGER_DEBUG("NativeTable Location 0x%p", location);

	//	address + 3
	//	48 8D 0D ?? ?? ?? ?? 48 8B 14 FA E8 ?? ?? ?? ?? 48 85 C0 75 0A
	// 0x00007FF68131A959
	char* address = Pattern::FindPattern<char*>(
		"\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\x14\xFA\xE8\x00\x00\x00\x00\x48\x85\xC0\x75\x0A",
		"xx?????xxxxx????xxxxx"
	);

	// 0x00007FF68131A95C
	char* location = reinterpret_cast<char*>(address + 3);
	LOGGER_DEBUG("Location 0x%p", location);

	// 0x00007FF682AEE930
	ScriptEngine::m_registrationTable = reinterpret_cast<NativeRegistration**>(location + *(int32_t*)location + 4);
	LOGGER_DEBUG("Pointeur 0x%p", ScriptEngine::m_registrationTable);

	CrossMapping::InitNativeMap();
}
void InitializePatterns()
{
	LOGGER_DEBUG("=============================================================================================");

	InitializeIsDLCPresent();
	LOGGER_DEBUG("=============================================================================================");

	InitializeFixVectors();
	LOGGER_DEBUG("=============================================================================================");

	InitializeNatives();
	LOGGER_DEBUG("=============================================================================================");
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
		LOGGER_FATAL("Failed scriptFiber");
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

// Hooks

// Detour function which overrides IS_DLC_PRESENT.
BOOL WINAPIV HK_IS_DLC_PRESENT(uint32_t dlcHash)
{
	// [00:34 : 40] DEBUG : HK_IS_DLC_PRESENT(2532323046)
	// [00:34 : 40] DEBUG : HK_IS_DLC_PRESENT(2603778600)
	// LOGGER_DEBUG("HK_IS_DLC_PRESENT(%u)", dlcHash);

	static int frameCount	= 0;
	int newFrameCount		= GAMEPLAY::GET_FRAME_COUNT();

	if (newFrameCount > frameCount)
	{
		frameCount = newFrameCount;

		Hooking::onTickInit();
	}

	if (dlcHash == 0x96F02EE6)
		return true;

	return fpIsDLCPresentOriginal(dlcHash);
}

BOOL Hooking::CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal)
{
	MH_STATUS status = MH_CreateHook(pTarget, pDetour, ppOriginal);

	if (status != MH_STATUS::MH_OK && status != MH_STATUS::MH_ERROR_ALREADY_CREATED)
	{
		LOGGER_ERROR("Failed to CreateHook : %s", MH_StatusToString(status));
		return false;
	}

	LOGGER_DEBUG("CreateHook : OK");
	return true;
}
BOOL Hooking::EnableHook(LPVOID pTarget)
{
	MH_STATUS status = MH_EnableHook(pTarget);

	if (status != MH_STATUS::MH_OK)
	{
		LOGGER_ERROR("Failed to MH_EnableHook : %s", MH_StatusToString(status));
		return false;
	}

	LOGGER_DEBUG("MH_EnableHook : OK");
	return true;
}

BOOL Hooking::HookNatives()
{
	bool success = CreateHook(
		fpIsDLCPresentTarget,
		HK_IS_DLC_PRESENT,
		reinterpret_cast<LPVOID*>(&fpIsDLCPresentOriginal)
	);
	return success ? EnableHook(fpIsDLCPresentTarget) : false;
}

BOOL Hooking::Initialize()
{
	InitializePatterns();

	LOGGER_DEBUG("----> Initialize Hooks...");

	BOOL returnVal = TRUE;

	// MH_Initialize
	MH_STATUS status = MH_Initialize();
	if (status == MH_STATUS::MH_OK)
		LOGGER_DEBUG("MH_Initialize Initialized OK");
	else {
		LOGGER_ERROR("Failed to MH_Initialize : %s", MH_StatusToString(status));

		returnVal = FALSE;
	}

	// HookNatives
	if (HookNatives())
		LOGGER_DEBUG("HookNatives Initialized OK");
	else {
		LOGGER_ERROR("Failed to initialize NativeHooks");
		returnVal = FALSE;
	}

	return returnVal;
}
BOOL Hooking::Uninitialize()
{
	// Disable the hook for IS_DLC_PRESENT.
	MH_STATUS status = MH_DisableHook(fpIsDLCPresentTarget);
	if (status != MH_STATUS::MH_OK)
	{
		LOGGER_ERROR("Failed to MH_DisableHook :%s\n", MH_StatusToString(status));
		return false;
	}
	LOGGER_DEBUG("MH_DisableHook : OK");

	// Remove the hook for IS_DLC_PRESENT.
	status = MH_RemoveHook(fpIsDLCPresentTarget);
	if (status != MH_STATUS::MH_OK)
	{
		LOGGER_ERROR("Failed to MH_RemoveHook :%s\n", MH_StatusToString(status));
		return false;
	}
	LOGGER_DEBUG("MH_RemoveHook : OK");

	// Uninitialize MinHook.
	status = MH_Uninitialize();
	if (status != MH_STATUS::MH_OK)
	{
		LOGGER_ERROR("Failed to MH_Uninitialize :%s\n", MH_StatusToString(status));
		return false;
	}

	return true;
}
