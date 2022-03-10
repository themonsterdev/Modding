#pragma once

// Native function handler type
typedef void(__cdecl* NativeHandler)(scrNativeCallContext* context);

struct NativeRegistration
{
	uint64_t		nextRegBase;
	uint64_t		nextRegKey;
	NativeHandler	handlers[7];
	uint32_t		numEntries1;
	uint32_t		numEntries2;
	uint64_t		hashes;

	inline NativeRegistration* getNextRegistration()
	{
		uintptr_t result;
		auto v5 = reinterpret_cast<uintptr_t>(&nextRegBase);
		auto v12 = 2i64;
		auto v13 = v5 ^ nextRegKey;
		auto v14 = (char*)&result - v5;
		do
		{
			*(DWORD*)&v14[v5] = (DWORD)(v13 ^ *(DWORD*)v5);
			v5 += 4i64;
			--v12;
		} while (v12);

		return reinterpret_cast<NativeRegistration*>(result);
	}

	inline uint32_t getNumEntries() {
		return static_cast<uint32_t>(reinterpret_cast<uint64_t>(&numEntries1)) ^ numEntries1 ^ numEntries2;
	}

	inline uint64_t getHash(uint32_t index)
	{
		auto naddr = 16 * index + reinterpret_cast<uintptr_t>(&nextRegBase) + 0x54;
		auto v8 = 2i64;
		uint64_t nResult;
		auto v11 = (char*)&nResult - naddr;
		auto v10 = naddr ^ *(DWORD*)(naddr + 8);
		do
		{
			*(DWORD*)&v11[naddr] = (DWORD)(v10 ^ *(DWORD*)(naddr));
			naddr += 4i64;
			--v8;
		} while (v8);

		return nResult;
	}
};

class ScriptEngine
{
public:

	static NativeRegistration** m_registrationTable;

	// Gets a native function handler
	static NativeHandler GetNativeHandler(uint64_t oldHash);

};
