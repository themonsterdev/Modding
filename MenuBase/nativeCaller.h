#pragma once

template <typename T>
static inline void nativePush(T val)
{
	UINT64 val64 = 0;

	if (sizeof(T) > sizeof(UINT64))
		throw "error, value size > 64 bit";

	*reinterpret_cast<T*>(&val64) = val; // &val + sizeof(dw) - sizeof(val)
	nativePush64(val64);
}

template<typename R, typename... A>
static inline R invoke(UINT64 hash, A &&... args)
{
	nativeInit(hash);
	int dummy[] = { 0, ((void)nativePush(forward<A>(args)), 0) ... };
	return *reinterpret_cast<R*>(nativeCall());
}
