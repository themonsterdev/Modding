// stdafx.h: fichier Include pour les fichiers Include système standard,
// ou les fichiers Include spécifiques aux projets qui sont utilisés fréquemment,
// et sont rarement changés
//

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclure les en-têtes Windows rarement utilisés

// Fichiers d'en-tête Windows
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Winmm.lib")

// référencer ici les en-têtes supplémentaires nécessaires à votre programme
#include <windows.h>
#include <Mmsystem.h>
#include <string>
#include <vector>
#include <intrin.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <Psapi.h>
#include <timeapi.h>
#include <time.h>
#include <locale>
#include <codecvt>
#include <stdio.h>
#include <array>

using namespace std;
#pragma execution_character_set("utf-8")

#define IsKeyPressed(key) GetAsyncKeyState(key) & 0x8000

#include <MinHook.h>

// Additional Header Files:
#include "Logger.h"

// Gta V
#include "types.h"
#include "enums.h"
#include "crossMapping.h"
#include "invoker.h"
#include "natives.h"

#include "script.h"
#include "pattern.h"
#include "scriptHooking.h"
#include "scriptEngine.h"
#include "hooking.h"
