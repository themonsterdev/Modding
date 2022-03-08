// stdafx.h: fichier Include pour les fichiers Include système standard,
// ou les fichiers Include spécifiques aux projets qui sont utilisés fréquemment,
// et sont rarement changés
//

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclure les en-têtes Windows rarement utilisés

// référencer ici les en-têtes supplémentaires nécessaires à votre programme
#include <Windows.h>
#include <TlHelp32.h>

#include <memory>
#include <string>

using namespace std;

// Additional Header Files:
#include "Logger.h"
#include "Process.h"
