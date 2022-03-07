#pragma once

#include "stdafx.h"

bool firstLoaded = false;

void DrawNotify(char* Text, int Time = 3000)
{
	UI::BEGIN_TEXT_COMMAND_PRINT((char*)"STRING");
	UI::ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME(Text);
	UI::END_TEXT_COMMAND_PRINT(Time, false);
}

void Update()
{
	if (!firstLoaded)
	{
		DrawNotify((char*)"Hack Loaded", 2000);
		firstLoaded = true;
	}
	
	if ((IsKeyPressed(VK_NUMPAD3)))
	{
		bool visible = ENTITY::IS_ENTITY_VISIBLE(PLAYER::PLAYER_PED_ID());
		ENTITY::SET_ENTITY_VISIBLE(PLAYER::PLAYER_PED_ID(), !visible, true);
		WAIT(100);
	}
}

bool ScriptMain()
{
	srand((unsigned long)GetTickCount64());

	while (true)
	{
		Update();
		WAIT(0);
	}

	return true;
}
