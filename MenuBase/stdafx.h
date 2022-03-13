// stdafx.h: fichier Include pour les fichiers Include système standard,
// ou les fichiers Include spécifiques aux projets qui sont utilisés fréquemment,
// et sont rarement changés
//

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclure les en-têtes Windows rarement utilisés

// Fichiers d'en-tête Windows
#include <Windows.h>

// référencer ici les en-têtes supplémentaires nécessaires à votre programme
#include <unordered_map>
using namespace std;

// Additional Header Files:
#include "logger.h"
#include "entry.h"

// Gta V
#include "types.h"
#include "enums.h"
#include "crossMapping.h"
#include "invoker.h"
#include "natives.h"

#include "pattern.h"

#include "script.h"
#include "scriptEngine.h"

#include "trampoline.h"
#include "hooking.h"
