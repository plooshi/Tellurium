#pragma once
#include "pch.h"
#include <array>
#include <string_view>
#include <intrin.h>

namespace Tellurium
{
    template <size_t Size>
    struct ConstexprString 
    {
        char Storage[Size];

    public:
        consteval ConstexprString(const char(&Str)[Size])
        {
            std::copy_n(Str, Size, Storage);
        }

        operator const char* () 
        {
            return Storage;
        }

        constexpr std::string_view StringView() const 
        {
            return Storage;
        }

        consteval uint32_t PatternCount() const 
        {
            int c = 0;

            for (int i = 0; i < Size; i++)
                if (Storage[i] == ' ') 
                    c++;

            return c + 1;
        }
    };

    namespace PE
    {
        inline uint64_t ImageBase = *(uint64_t*)(__readgsqword(0x60) + 0x10);

        IMAGE_SECTION_HEADER* GetSection(const char* name);
    }

    namespace Patchfinder
    {
        consteval int PatternCount(std::string_view s) 
        {
            int c = 0;

            for (int i = 0; i < s.size(); i++) 
            {
                if (s[i] == ' ') 
                    c++;
            }

            return c + 1;
        }
        consteval uint16_t parsePatternPart(std::string_view s) 
        {
            uint8_t val = 0;
            bool bEnable = true;
            for (int i = 0; i < s.size(); i++) 
            {
                uint8_t byte = s[i];

                if (byte >= '0' && byte <= '9') 
                    byte = byte - '0';
                else if (byte >= 'a' && byte <= 'f') 
                    byte = byte - 'a' + 10;
                else if (byte >= 'A' && byte <= 'F') 
                    byte = byte - 'A' + 10;
                else if (byte == '?')
                {
                    byte = 0;
                    bEnable = false;
                }

                val = (val << 4) | (byte & 0xF);
            }
            return (bEnable << 8) | val;
        }

        uint64_t InternalFindPattern(const uint8_t* Bytes, const uint8_t* Enabled, uint32_t Size, bool bInRData);

        template <ConstexprString Str, bool bInRData = false>
        struct Pattern
        {
        private:
            uint8_t Bytes[Str.PatternCount()] = { 0 };
            uint8_t Enabled[(Str.PatternCount() + (Str.PatternCount() % 8 ? 8 - (Str.PatternCount() % 8) : 0)) / 8] = { 0 };
        public:

            consteval Pattern()
            {
                constexpr auto st = Str.StringView();
                constexpr auto arrsz = Str.PatternCount();
                std::array<uint8_t, arrsz> NewBytes = { 0 };
                std::array<uint8_t, Str.PatternCount() + 8 - (Str.PatternCount() % 8)> NewEnabled = { 0 };
                size_t cInd = 0;

                for (int i = 0; i < arrsz; i++) 
                {
                    auto part = st.substr(cInd, st.find_first_of(' ', cInd) == std::string_view::npos ? st.size() - cInd : (st.find_first_of(' ', cInd) + 1) - cInd - 1);
                    auto parsed = parsePatternPart(part);

                    Bytes[i] = parsed & 0xFF;
                    if (parsed & 0x100)
                        Enabled[i / 8] |= (1 << (i % 8));

                    cInd = st.find_first_of(' ', cInd) + 1;
                }
            }

            constexpr uint64_t Scan() const
            {
                return InternalFindPattern(Bytes, Enabled, Str.PatternCount(), bInRData);
            }
        };

        uint64_t InternalFindStringRef(const void* string, size_t sLen);
        
        template <typename T>
        uint64_t FindStringRef(T string)
        {
            constexpr auto bIsWide = std::is_same<T, const wchar_t*>::value;
            constexpr auto bIsChar = std::is_same<T, const char*>::value;

            constexpr auto bIsPtr = bIsWide || bIsChar;

            size_t slen = 0;
            if constexpr (bIsWide)
                slen = (wcslen(string) + 1) * sizeof(wchar_t);
            else if constexpr (bIsChar)
                slen = strlen(string) + 1;

            return InternalFindStringRef(string, slen);
        }

        bool InternalCheckBytes(uint64_t base, int ind, const uint8_t* bytes, size_t sz, bool upwards = false);
        template <uint8_t... Data>
        class CheckBytes 
        {
        public:
            constexpr static uint8_t bytes[sizeof...(Data)] = { Data... };
            uint64_t Base;
            int Ind;
            bool Upwards;

            CheckBytes(uint64_t base, int ind, bool upwards = false) 
            {
                Base = base;
                Ind = ind;
                Upwards = upwards;
            }

            operator bool() 
            {
                return InternalCheckBytes(Base, Ind, bytes, sizeof...(Data), Upwards);
            }
        };
    }
}
