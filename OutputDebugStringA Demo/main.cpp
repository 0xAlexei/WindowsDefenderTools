#include <Windows.h>

/*
Make sure you build as x86 Release

I've found that the Visual Studio project configuration I've set up for this
project results in a binary that is consistently emulated when run. As my
presentation details, as you create more complex binaries, you may run 
into situations where Defender fails to emulate your binary, or only emulates
it partially.
*/

int entrypoint()
{
	OutputDebugStringA("This is coming from inside the emulator!");

	return 0;
}
