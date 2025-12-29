#include <Windows.h>
#include "pch.h"
#include "ModUtils.h"

using namespace ModUtils;
using namespace mINI;

bool skipIntroLogos = true;

DWORD WINAPI MainThread(LPVOID lpParam)
{
    if (!skipIntroLogos)
        return 0;

    Log("Scanning for Intro Logos code...");

    // Stable, fork-friendly AOB
    std::string aob1 =
        "3b be ? ? ? ? 75 ? 80 be ? ? ? ? 00 74 05 40 b5 01";

    // JE -> JMP (force skip)
    std::string expectedBytes = "74 05";
    std::string newBytes = "eb 05";

    uintptr_t aobAddress = AobScan(aob1);

    if (aobAddress)
    {
        // JE opcode is at +15 from AOB start
        uintptr_t targetAddress = aobAddress + 15;

        Log("Intro Logo Code found at %p", (void*)targetAddress);
        Log("Patching JE -> JMP...");

        ReplaceExpectedBytesAtAddress(
            targetAddress,
            expectedBytes,
            newBytes
        );
    }
    else
    {
        Log("Error: Could not find Intro Logo AOB.");
    }

    CloseLog();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
