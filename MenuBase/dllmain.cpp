// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

static HANDLE g_hThread		= nullptr;
static DWORD g_dwThreadId	= 0;

void StopThread(HMODULE hModule);

DWORD WINAPI StartThread(LPVOID lpParam)
{
	HMODULE hModule = reinterpret_cast<HMODULE>(lpParam);

	Hooking::Start(hModule);

	while (true)
	{
		if (IsKeyPressed(VK_NUMPAD2))
			break;

		Sleep(300);
	}

	StopThread(hModule);

	return 0;
}

void StopThread(HMODULE hModule)
{
	Hooking::Stop();

	DEBUGMSG("FreeLibraryAndExitThread");
	FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Disable les notifications DLL_THREAD_ATTACH and DLL_THREAD_DETACH.
		DisableThreadLibraryCalls(hModule);

		// Create the thread to begin execution on its own.
		g_hThread = CreateThread(
			nullptr,                // default security attributes
			0,                      // use default stack size  
			StartThread,            // thread function name
			hModule,                // argument to thread function 
			0,                      // use default creation flags 
			&g_dwThreadId			// returns the thread identifier
		);

		if (g_hThread == 0)
			ExitProcess(3);
		break;
	}
	return TRUE;
}
