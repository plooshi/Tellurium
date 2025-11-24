#include "pch.h"
#include "Patchfinder.h"

IMAGE_SECTION_HEADER* Tellurium::PE::GetSection(const char* name)
{
    IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)ImageBase;
    auto PEHeader = (IMAGE_NT_HEADERS*)(ImageBase + dos_hdr->e_lfanew);
    auto StartOfSects = IMAGE_FIRST_SECTION(PEHeader);

    for (int i = 0; i < PEHeader->FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER* Section = StartOfSects + i;

        if (strncmp((const char*)Section->Name, name, 8) == 0)
            return Section;
    }

    return nullptr;
}

uint64_t Tellurium::Patchfinder::InternalFindPattern(const uint8_t* Bytes, const uint8_t* Enabled, uint32_t Size, bool bInRData)
{
    auto startingByte = Bytes[0];
    uint32_t h = 1;
    bool bIsEnabled = *Enabled & 1;
    while (!bIsEnabled && h < Size)
    {
        startingByte = Bytes[h];
        bIsEnabled = Enabled[h / 8] & (1 << (h % 8));
        h++;
    }

    auto scanSect = bInRData ? PE::GetSection(".rdata") : PE::GetSection(".text");
    const auto scanBytes = (uint8_t*)(PE::ImageBase + scanSect->VirtualAddress);
    const auto sizeOfImage = scanSect->Misc.VirtualSize;

    __m128i t = _mm_set1_epi8((char)startingByte);

    size_t i = 0;
    for (; i < (sizeOfImage - Size) - ((sizeOfImage - Size) % 16); i += 16)
    {
        auto bytes = _mm_load_si128((const __m128i*)(scanBytes + i));
        int offset = _mm_movemask_epi8(_mm_cmpeq_epi8(bytes, t));

        if (offset == 0)
            continue;

        for (int q = 0; q < 16; q++)
        {
            int c = offset & (1 << q);
            if (c)
            {
                bool found = true;
                for (auto j = h; j < Size; ++j)
                {
                    if (Enabled[j / 8] & (1 << (j % 8)) && scanBytes[i + q + j] != Bytes[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                    return __int64(scanBytes + i + q);
            }
        }
    }

    for (; i < sizeOfImage - Size; i++)
    {
        bool found = true;
        for (auto j = h; j < Size; ++j)
        {
            if (Enabled[j / 8] & (1 << (j % 8)) && scanBytes[i + j] != Bytes[j])
            {
                found = false;
                break;
            }
        }

        if (found)
            return __int64(scanBytes + i);
    }

    return 0;
}

uint64_t Tellurium::Patchfinder::InternalFindStringRef(const void* string, size_t sLen)
{
    auto textSection = PE::GetSection(".text");
    auto rdataSection = PE::GetSection(".rdata");

    const auto scanBytes = (uint8_t*)(PE::ImageBase + textSection->VirtualAddress);
    const auto sizeOfImage = textSection->Misc.VirtualSize;

    const auto rdataStart = (uint8_t*)(PE::ImageBase + rdataSection->VirtualAddress);
    const auto rdataEnd = rdataStart + rdataSection->Misc.VirtualSize;

    DWORD i = 0x0;

    //__m128i t = _mm_set1_epi8(0x48);
    //__m128i s = _mm_set1_epi8((char)0xfb);
    __m128i t = _mm_set1_epi8((char)0x8d);

    for (; i < sizeOfImage - (sizeOfImage % 16); i += 16)
    {
        auto bytes = _mm_load_si128((const __m128i*)(scanBytes + i));
        //__m128i masked = _mm_and_si128(bytes, s);
        int offset = _mm_movemask_epi8(_mm_cmpeq_epi8(bytes, t));

        if (offset == 0)
            continue;

        for (int q = 0; q < 16; q++)
        {
            int c = offset & (1 << q);

            if (c)
            {
                //if (scanBytes[i + q + 1] == 0x8D)
                if ((scanBytes[i + q - 1] & 0xfb) == 0x48)
                {
                    auto stringAdd = (&scanBytes[i + q] + 6) + *(int32_t*)(&scanBytes[i + q] + 2);

                    if (stringAdd >= rdataStart && stringAdd < rdataEnd)
                    {
                        if (memcmp(string, stringAdd, sLen) == 0)
                            return uint64_t(&scanBytes[i + q - 1]);
                    }
                }
            }
        }
    }

    return 0;
}

__declspec(noinline) bool Tellurium::Patchfinder::InternalCheckBytes(uint64_t base, int ind, const uint8_t* bytes, size_t sz, bool upwards)
{
    auto offBase = (uint8_t*)(upwards ? base - ind : base + ind);

    for (int i = 0; i < sz; i++)
        if (*(offBase + i) != bytes[i]) 
            return false;

    return true;
}