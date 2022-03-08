#include "stdafx.h"

char* GetLogFilepath(string arg0, const char* dllFilename)
{
	static char filepath[MAX_PATH];
	strcpy_s(filepath, arg0.substr(0, arg0.length() - 12).c_str());
	strcat_s(filepath, dllFilename);
	return filepath;
}

int main(int argc, char* argv[])
{
	char processName[]				= "GTA5.exe";
	char moduleName[]				= "MenuBase.dll";
	char injectorName[]				= "Injector";

	// Logger
	char* loggerPath				= GetLogFilepath(argv[0], injectorName);
	Logger::Init(loggerPath);

	// Process
	shared_ptr<Process> gtavProcess = make_shared<Process>(processName);
	DWORD processId					= gtavProcess->GetProcessId();
	gtavProcess->GetModuleBaseAddress(processId);

	// Module
	char* modulePath				= GetLogFilepath(argv[0], moduleName);

	// Inject
	if (gtavProcess->InjectModule(processId, modulePath) == 0)
	{
		LOGGER_ERROR("Failed to inject <%s>.", moduleName);
		return EXIT_FAILURE;
	}

	LOGGER_DEBUG("Successfully Injected module <%s> :).", moduleName);
	return EXIT_SUCCESS;
}
