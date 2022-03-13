#pragma once

typedef unordered_map<uint64_t, uint64_t> nMap;
static vector<uint64_t> nativeFailedVec;

class CrossMapping
{
public:

	static void		InitNativeMap();
	static uint64_t MapNative(uint64_t inNative);
	static bool		SearchMap(nMap map, uint64_t inNative, uint64_t* outNative);

};
