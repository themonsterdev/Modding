#pragma once

class Hooking
{
public:

	static BOOL Initialize();
	static BOOL Uninitialize();

	static void onTickInit();

};

LPVOID AllocatePageNearAddress(LPVOID pTarget);
VOID WriteAbsoluteJump64(LPVOID absoluteJumpMemory, LPVOID addrToJumpTo);

VOID InstallHook(LPVOID pTarget, LPVOID pRetour, LPVOID* ppOriginal);
VOID UninstallHook(LPVOID pTarget);

void WAIT(DWORD ms);
