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

LPVOID AllocatePageNearAddress(LPVOID pTarget);
VOID WriteAbsoluteJump64(LPVOID absoluteJumpMemory, LPVOID addrToJumpTo);

VOID InstallHook(LPVOID pTarget, LPVOID pRetour, LPVOID* ppOriginal);
VOID UninstallHook(LPVOID pTarget);

void WAIT(DWORD ms);
