#include "pch.h"
#include "Hooks.h"
#include "Patchfinder.h"
#include "Options.h"

bool InitializeForModule(uint64_t Module, void* Hook, void** OG, bool EOS)
{
    Tellurium::PE::ImageBase = Module;

    auto processRequestStr = Tellurium::Patchfinder::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest");

    if (!processRequestStr)
        processRequestStr = Tellurium::Patchfinder::FindStringRef(L"%p: request (easy handle:%p) has been added to threaded queue for processing");

    if (!processRequestStr)
        return false;

    uint64_t ProcessRequest = 0;
    for (int i = 0; i < 2048; i++)
    {
        if (EOS)
        {
            if (Tellurium::Patchfinder::CheckBytes<0x48, 0x89, 0x5C>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
        }
        else
        {
            if (Tellurium::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
            else if (Tellurium::Patchfinder::CheckBytes<0x48, 0x8B, 0xC4>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
            else if (Tellurium::Patchfinder::CheckBytes<0x48, 0x81, 0xEC>(processRequestStr, i, true) || Tellurium::Patchfinder::CheckBytes<0x48, 0x83, 0xEC>(processRequestStr, i, true))
            {
                for (int x = 0; x < 50; x++)
                {
                    if (Tellurium::Patchfinder::CheckBytes<0x40>(processRequestStr, i + x, true))
                    {
                        ProcessRequest = processRequestStr - i - x;
                        goto _found;
                    }
                    else if (Tellurium::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(processRequestStr, i + x, true) || Tellurium::Patchfinder::CheckBytes<0x48, 0x8B, 0xC4>(processRequestStr, i + x, true) || Tellurium::Patchfinder::CheckBytes<0x48, 0x89, 0x5C>(processRequestStr, i + x, true))
                        break;
                }
            }
        }
    }

    if (!ProcessRequest)
        return false;
_found:
    auto rdataSection = Tellurium::PE::GetSection(".rdata");
    const auto rdataStart = (uint8_t*)(Tellurium::PE::ImageBase + rdataSection->VirtualAddress);
    const auto rdataEnd = rdataStart + rdataSection->Misc.VirtualSize;

    uint64_t ProcessRequestVFT = 0;
    __m128i t = _mm_set1_epi32((int)(ProcessRequest & 0xffffffff));
    for (uint32_t i = 0; i < rdataSection->Misc.VirtualSize - (rdataSection->Misc.VirtualSize % 16); i += 16)
    {
        auto bytes = _mm_load_si128((const __m128i*)(rdataStart + i));
        int offset = _mm_movemask_epi8(_mm_cmpeq_epi32(bytes, t));

        if (offset == 0)
            continue;

        for (int q = 0; q < 16; q += 4)
        {
            int c = offset & (1 << q);
            if (c)
            {
                auto VFT = (uint64_t*)(rdataStart + i + q);

                if (*VFT == ProcessRequest)
                {
                    ProcessRequestVFT = uint64_t(VFT);
                    goto _foundVFT;
                }
            }
        }
    }

    if (!ProcessRequest)
        return false;

_foundVFT:
    DWORD oldProt;
    VirtualProtect(LPVOID(ProcessRequestVFT), sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);

    if (OG)
        *OG = (void*)ProcessRequest;

    *(void**)ProcessRequestVFT = Hook;

    VirtualProtect(LPVOID(ProcessRequestVFT), sizeof(void*), oldProt, &oldProt);

    return true;
}

bool ProcessRequestHook(Tellurium::Unreal::FCurlHttpRequest* _this)
{
    _this->RedirectRequest(false);
    return Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG(_this);
}

bool ProcessRequest__EOS(Tellurium::Unreal::FCurlHttpRequest* _this)
{
    _this->RedirectRequest(true);
    return Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG__EOS(_this);
}

bool bInit = false;
void Tellurium::Hooks::Init()
{
    if (Console)
    {
        AllocConsole();

        FILE* fptr;
        freopen_s(&fptr, "CONOUT$", "w+", stdout);
        SetConsoleTitleA("Tellurium (https://github.com/plooshi/Tellurium)");
    }

    if (UseBackendParam)
    {
        Tellurium::Unreal::FString cmd = GetCommandLineW();
        auto pos = cmd.find(L"-backend=");
        if (pos != Tellurium::Unreal::FString::npos)
            Tellurium::Unreal::backend = cmd.substr(pos + 9);
        else
            Tellurium::Unreal::backend = Backend;
    }

    constexpr static auto ReallocSig = Tellurium::Patchfinder::Pattern<"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?">();
    while (!Tellurium::Unreal::FMemory__Realloc)
        Tellurium::Unreal::FMemory__Realloc = ReallocSig.Scan();

    while (!InitializeForModule(Tellurium::PE::ImageBase, ProcessRequestHook, (void**)&Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG, false));

    auto EOSBuf = LoadLibraryA("EOSSDK-Win64-Shipping");

    if (EOSBuf)
    {
        InitializeForModule(uint64_t(EOSBuf), ProcessRequest__EOS, (void**)&Tellurium::Unreal::FCurlHttpRequest::ProcessRequestOG__EOS, true);

        // pushwidget isnt on pre-EOS builds
        if (bHasPushWidget)
        {
            Tellurium::PE::ImageBase = *(uint64_t*)(__readgsqword(0x60) + 0x10);
            constexpr static auto PushWidget1 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B E9 49 8B D9 48 8D 0D ? ? ? ? 49 8B F8 48 8B F2 E8 ? ? ? ? 4C 8B CF 48 89 5C 24 ? 4C 8B C6 48 8B D5 48 8B 48 78">();
            constexpr static auto PushWidget2 = Tellurium::Patchfinder::Pattern<"48 8B C4 4C 89 40 18 48 89 50 10 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 B8 48 81 EC ? ? ? ? 65 48 8B 04 25">();
            constexpr static auto PushWidget3 = Tellurium::Patchfinder::Pattern<"48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8B F9 B9 ? ? ? ?">();

            if (PushWidget1.Scan() || PushWidget2.Scan() || PushWidget3.Scan())
            {
                constexpr static auto RequestExitWithStatus1 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?">();
                constexpr static auto RequestExitWithStatus2 = Tellurium::Patchfinder::Pattern<"48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30">();
                constexpr static auto RequestExitWithStatus3 = Tellurium::Patchfinder::Pattern<"4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B">();

                auto RequestExitWithStatus = RequestExitWithStatus1.Scan();

                if (!RequestExitWithStatus)
                    RequestExitWithStatus = RequestExitWithStatus2.Scan();

                if (!RequestExitWithStatus)
                    RequestExitWithStatus = RequestExitWithStatus3.Scan();

                constexpr static auto ShowAppEnvironmentSecurityMessage1 = Tellurium::Patchfinder::Pattern<"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8">();
                constexpr static auto ShowAppEnvironmentSecurityMessage2 = Tellurium::Patchfinder::Pattern<"40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?">();
                constexpr static auto ShowAppEnvironmentSecurityMessage3 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1">();
                constexpr static auto ShowAppEnvironmentSecurityMessage4 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?">();
                constexpr static auto ShowAppEnvironmentSecurityMessage5 = Tellurium::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8">();
                constexpr static auto ShowAppEnvironmentSecurityMessage6 = Tellurium::Patchfinder::Pattern<"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?">();

                auto ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage1.Scan();

                if (!ShowAppEnvironmentSecurityMessage)
                    ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage2.Scan();

                if (!ShowAppEnvironmentSecurityMessage)
                    ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage3.Scan();

                if (!ShowAppEnvironmentSecurityMessage)
                    ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage4.Scan();

                if (!ShowAppEnvironmentSecurityMessage)
                    ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage5.Scan();

                if (!ShowAppEnvironmentSecurityMessage)
                    ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage6.Scan();

                if (RequestExitWithStatus)
                {
                    DWORD oldProt;
                    VirtualProtect(LPVOID(RequestExitWithStatus), 1, PAGE_EXECUTE_READWRITE, &oldProt);

                    *(uint8_t*)RequestExitWithStatus = 0xC3;

                    VirtualProtect(LPVOID(RequestExitWithStatus), 1, oldProt, &oldProt);
                }

                if (ShowAppEnvironmentSecurityMessage)
                {
                    DWORD oldProt;
                    VirtualProtect(LPVOID(ShowAppEnvironmentSecurityMessage), 1, PAGE_EXECUTE_READWRITE, &oldProt);

                    *(uint8_t*)ShowAppEnvironmentSecurityMessage = 0xC3;

                    VirtualProtect(LPVOID(ShowAppEnvironmentSecurityMessage), 1, oldProt, &oldProt);
                }
            }
        }
    }

    bInit = true;
}