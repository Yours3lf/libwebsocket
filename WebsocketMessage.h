#pragma once

#include <vector>

enum frameType
{
	FRAME_CONTINUATION = 0x0,
	FRAME_TEXT = 0x1,
	FRAME_BINARY = 0x2,
	FRAME_CLOSE = 0x8,
	FRAME_PING = 0x9,
	FRAME_PONG = 0xa
};

struct websocketMessage
{
	std::vector<char> buf;
	frameType type;
};