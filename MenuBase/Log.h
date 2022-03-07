#pragma once

#ifdef __DEBUG
#define DEBUGOUT( X, ... ) Log::Debug( X, __VA_ARGS__ )
#define DEBUGOUT( X, ... ) Log::Msg_Simple( X, __VA_ARGS__ )
#else
#define DEBUGOUT( X, ... )
//#define DEBUGMSG_S( X, ... )
#endif

#if _DEBUG
#define DEBUGMSG Log::Debug
#define DEBUGMSG_S Log::Msg_Simple
#else
#define DEBUGMSG //
#define DEBUGMSG_S
#endif

class Log
{
public:
	static void Init(HMODULE hModule);
#ifdef _DEBUG
	static void Debug(const char* fmt, ...);
	static void Msg_Simple(const char* Path, const char* fmt, ...);
#endif
	static void Msg(const char* fmt, ...);

	static void Error(const char* fmt, ...);
	static void Fatal(const char* fmt, ...);

	//static void Cree_file_log(const char *filepath, const char *text, bool clearing);
	//static void Msg_Dev(const char* fmt, bool clearing = false);

};
