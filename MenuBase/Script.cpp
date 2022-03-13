#pragma once

#include "stdafx.h"

void TEXT_COMMAND_PRINT(char* Text, int Time = 3000)
{
	UI::BEGIN_TEXT_COMMAND_PRINT("STRING");
	UI::ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME(Text);
	UI::END_TEXT_COMMAND_PRINT(Time, false);
}

void teleportPlayer(float x, float y, float z)
{
	Entity teleportEntity = PLAYER::PLAYER_PED_ID();

	if (PED::IS_PED_IN_ANY_VEHICLE(teleportEntity, false))
	{
		teleportEntity = PED::GET_VEHICLE_PED_IS_USING(teleportEntity);
	}

	ENTITY::SET_ENTITY_COORDS(teleportEntity, x, y, z, false, false, false, false);
}

void Update()
{
	static bool loadedPrint = true;

	Player player = PLAYER::PLAYER_ID();
	GAMEPLAY::SET_SUPER_JUMP_THIS_FRAME(player);
	ENTITY::SET_ENTITY_INVINCIBLE(player, true);

	if (CONTROLS::IS_CONTROL_JUST_PRESSED(0, INPUT_FRONTEND_X)) {
		teleportPlayer(-74.94243f, -818.63446f, 326.174347f); // Top of Maze Bank
	}

	if (loadedPrint)
	{
		TEXT_COMMAND_PRINT("Hack Loaded", 2000);
		loadedPrint = false;
	}

	if (GetAsyncKeyState(VK_NUMPAD3) & 0x01)
	{
		bool visible = ENTITY::IS_ENTITY_VISIBLE(PLAYER::PLAYER_PED_ID());
		ENTITY::SET_ENTITY_VISIBLE(PLAYER::PLAYER_PED_ID(), !visible, true);
	}
}
