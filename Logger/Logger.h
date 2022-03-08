#pragma once

#if _DEBUG
#define LOGGER_DEBUG Logger::Debug
#else
#define LOGGER_DEBUG
#endif

#define LOGGER_DEBUG Logger::Debug
#define LOGGER_ERROR Logger::Error
#define LOGGER_FATAL Logger::Fatal
#define LOGGER_LOG	 Logger::Log

class Logger
{
public:

	static void Init(const char* filepath);

#ifdef _DEBUG
	static void Debug(const char* fmt, ...);
#endif

	static void Log(const char* fmt, ...);

	static void Error(const char* fmt, ...);
	static void Fatal(const char* fmt, ...);

};
