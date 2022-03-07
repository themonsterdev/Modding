#pragma once

typedef void(__cdecl* NativeHandler)(scrNativeCallContext*);

class Hooking
{
private:

	static BOOL InitializeHooks();
	static void FindPatterns(HMODULE hModule);

public:

	static void Start(HMODULE);
	static void Stop();

	static void onTickInit();
	static bool HookNatives();

	static NativeHandler GetNativeHandler(uint64_t hash);
};

void WAIT(DWORD ms);
