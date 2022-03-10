#pragma once

class Hooking
{
private:

	static BOOL CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal);
	static BOOL EnableHook(LPVOID pTarget);

public:

	static BOOL Initialize();
	static BOOL Uninitialize();

	static void onTickInit();
	static BOOL HookNatives();

};

void WAIT(DWORD ms);
