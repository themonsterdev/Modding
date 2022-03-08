// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

static HANDLE g_hThread		= nullptr;
static DWORD g_dwThreadId	= 0;

void StopThread(HMODULE hModule);

char* GetModuleFilepath(HMODULE hModule)
{
	static char moduleFilepath[MAX_PATH];
	memset(moduleFilepath, 0, sizeof moduleFilepath);
	GetModuleFileNameA(hModule, moduleFilepath, MAX_PATH);
	return moduleFilepath;
}

char* GetModuleFolder(char* moduleFilepath, const char* filepath)
{
	size_t slash = -1;
	for (size_t i = 0; i < strlen(moduleFilepath); i++)
	{
		if (moduleFilepath[i] == '/' || moduleFilepath[i] == '\\')
		{
			slash = i;
		}
	}

	if (slash != -1)
	{
		moduleFilepath[slash + 1] = '\0';

		static char moduleFolderPath[MAX_PATH];
		strcpy_s(moduleFolderPath, moduleFilepath);
		strcat_s(moduleFolderPath, filepath);
		return moduleFolderPath;
	}

	return nullptr;
}

DWORD WINAPI StartThread(LPVOID lpParam)
{
	HMODULE hModule = reinterpret_cast<HMODULE>(lpParam);

	AllocConsole();
	FILE* pFile;
	freopen_s(&pFile, "CONIN$", "r", stdin);
	freopen_s(&pFile, "CONOUT$", "w", stderr);
	freopen_s(&pFile, "CONOUT$", "w", stdout);

	char* filepath		= GetModuleFilepath(hModule);
	char* folderpath	= GetModuleFolder(filepath, "MenuBase");

	Logger::Init(folderpath);
	LOGGER_DEBUG("AAA %s", folderpath);

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

	LOGGER_DEBUG("FreeConsole");
	FreeConsole(); // Free console require for freeze gtav

	FreeLibraryAndExitThread(hModule, EXIT_SUCCESS);
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
