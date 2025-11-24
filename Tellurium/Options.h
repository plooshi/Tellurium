#pragma once
#include "Unreal.h"

enum Tellurium__URLSet
{
	Default, // default for private servers
	Hybrid, // redirect profile, version, and content pages to private server, otherwise use official servers
	Dev, // redirect profile & content pages to private server, otherwise use official servers
	All, // redirect every request to private server
};

constexpr bool Console = false; // create console window (this does NOT create unreal console)
constexpr auto URLSet = Tellurium__URLSet::Default;
constexpr inline Tellurium::Unreal::FString Backend = L"http://127.0.0.1:3551"; // your backend url
constexpr bool bHasPushWidget = false; // fortnite: enable if you have gs closing after a couple seconds of listening. breaks closing the client (so don't build with this enabled for usage in a launcher.)

// misc options, don't change unless you know what you're doing
constexpr bool UseBackendParam = false; // for phoenix/paradise launcher
constexpr bool ManualMapping = false; // if you're using EAC & a manual mapper, then enable this for the dll to work
constexpr bool FixMemLeak = true; // memory leak fix