#include "stdafx.h"

#define CHARS_FOR_BUFF		4096
#define CHARS_FOR_PARAMS	3500

char g_logFilename[MAX_PATH];

void Logger::Init(const char* filepath)
{
	memset(g_logFilename, 0, sizeof g_logFilename);
	strcpy_s(g_logFilename, filepath);
	strcat_s(g_logFilename, ".log");

	char chLogBuff[CHARS_FOR_BUFF];
	sprintf_s(chLogBuff, "INIT: Logger\n");

	FILE* file;
	if ((fopen_s(&file, g_logFilename, "w")) == 0)
	{
		fprintf_s(file, "%s", chLogBuff);
		fclose(file);
	}
}

#ifdef _DEBUG
void Logger::Debug(const char* fmt, ...)
{
	va_list va_alist;
	char chLogBuff[CHARS_FOR_BUFF];
	char chParameters[CHARS_FOR_PARAMS];

	char szTimestamp[30];
	struct tm current_tm;
	time_t current_time = time(NULL);

	localtime_s(&current_tm, &current_time);
	sprintf_s(szTimestamp, "[%02d:%02d:%02d] DEBUG: %%s\n", current_tm.tm_hour, current_tm.tm_min, current_tm.tm_sec);

	va_start(va_alist, fmt);
	_vsnprintf_s(chParameters, sizeof(chParameters), fmt, va_alist);
	va_end(va_alist);
	sprintf_s(chLogBuff, szTimestamp, chParameters);

	FILE* file;
	if ((fopen_s(&file, g_logFilename, "a")) == 0)
	{
		fprintf_s(file, "%s", chLogBuff);
		fclose(file);
	}

	printf("%s", chLogBuff);
}
#endif

void Logger::Log(const char* fmt, ...)
{
	va_list va_alist;
	char chLogBuff[CHARS_FOR_BUFF];
	char chParameters[CHARS_FOR_PARAMS];

	char szTimestamp[30];
	struct tm current_tm;
	time_t current_time = time(NULL);

	localtime_s(&current_tm, &current_time);
	sprintf_s(szTimestamp, "[%02d:%02d:%02d] LOG: %%s\n", current_tm.tm_hour, current_tm.tm_min, current_tm.tm_sec);

	va_start(va_alist, fmt);
	_vsnprintf_s(chParameters, sizeof(chParameters), fmt, va_alist);
	va_end(va_alist);

	//sprintf_s(chLogBuff, chParameters);
	sprintf_s(chLogBuff, szTimestamp, chParameters);

	FILE* file;
	if ((fopen_s(&file, g_logFilename, "a")) == 0)
	{
		fprintf_s(file, "%s", chLogBuff);
		fclose(file);
	}

	sprintf_s(chLogBuff, "%s\n", chParameters);
	OutputDebugStringA(chLogBuff);
	printf("%s\n", chLogBuff);
}

void Logger::Error(const char* fmt, ...)
{
	va_list va_alist;
	char chLogBuff[CHARS_FOR_BUFF];
	char chParameters[CHARS_FOR_PARAMS];
	char szTimestamp[30];
	struct tm current_tm;
	time_t current_time = time(NULL);
	FILE* file;

	localtime_s(&current_tm, &current_time);
	sprintf_s(szTimestamp, "[%02d:%02d:%02d] ERROR: %%s\n", current_tm.tm_hour, current_tm.tm_min, current_tm.tm_sec);

	va_start(va_alist, fmt);
	_vsnprintf_s(chParameters, sizeof(chParameters), fmt, va_alist);
	va_end(va_alist);
	sprintf_s(chLogBuff, szTimestamp, chParameters);
	if ((fopen_s(&file, g_logFilename, "a")) == 0)
	{
		fprintf_s(file, "%s", chLogBuff);
		fclose(file);
	}

	MessageBoxA(NULL, chLogBuff, "ERROR", MB_ICONERROR);
	printf("%s\n", chLogBuff);
}

void Logger::Fatal(const char* fmt, ...)
{
	va_list va_alist;
	char chLogBuff[CHARS_FOR_BUFF];
	char chParameters[CHARS_FOR_PARAMS];
	char szTimestamp[30];
	struct tm current_tm;
	time_t current_time = time(NULL);
	FILE* file;

	localtime_s(&current_tm, &current_time);
	sprintf_s(szTimestamp, "[%02d:%02d:%02d] FATAL: %%s\n", current_tm.tm_hour, current_tm.tm_min, current_tm.tm_sec);

	va_start(va_alist, fmt);
	_vsnprintf_s(chParameters, sizeof(chParameters), fmt, va_alist);
	va_end(va_alist);
	sprintf_s(chLogBuff, szTimestamp, chParameters);
	if ((fopen_s(&file, g_logFilename, "a")) == 0)
	{
		fprintf_s(file, "%s", chLogBuff);
		fclose(file);
	}

	MessageBoxA(NULL, chLogBuff, "FATAL ERROR", MB_ICONERROR);
	printf("%s\n", chLogBuff);
	ExitProcess(0);
}
