#pragma once
#include "pch.h"
#include "Patchfinder.h"

namespace Tellurium
{
    namespace Unreal 
    {
        inline uint64_t FMemory__Realloc = 0;

        class FMemory
        {
        public:
            static __forceinline void* InternalRealloc(void* _a1, __int64 _a2, unsigned int _a3)
            {
                return ((void* (*&)(void*, __int64, unsigned int)) FMemory__Realloc)(_a1, _a2, _a3);
            }

            template<typename T = void>
            static inline T* Realloc(void* Ptr, uint64_t Size, int32_t Alignment = 0x0)
            {
                return (T*)InternalRealloc(Ptr, Size, Alignment);
            }

            template<typename T>
            static inline T* ReallocForType(void* Ptr, uint64_t Count, int32_t Size = sizeof(T))
            {
                return (T*)InternalRealloc(Ptr, Count * Size, alignof(T));
            }


            template<typename T = void>
            static inline T* Malloc(uint64_t Size, int32_t Alignment = 0x0)
            {
                return Realloc<T>(nullptr, Size, Alignment);
            }

            template<typename T>
            static inline T* MallocForType(uint64_t Count, int32_t Size = sizeof(T))
            {
                return ReallocForType<T>(nullptr, Count, Size);
            }

            static inline void Free(void* ptr)
            {
                Realloc(ptr, 0, 0);
            }

            template<typename T>
            static inline void FreeForType(T* ptr)
            {
                ReallocForType<T>(ptr, 0);
            }
        };
        class FString
        {
        public:
            wchar_t* String;
            uint32_t Length;
            uint32_t MaxSize;
            inline static const size_t npos = -1;
            FString();

            FString(const char* Other);

            FString(wchar_t* Other);

            consteval FString(const wchar_t* Other) 
            {
                if (Other) {
                    MaxSize = Length = (int)std::wstring_view(Other).size() + 1;
                    String = (wchar_t*)Other;
                }
            }


            consteval FString(const wchar_t* Other, size_t len) 
            {
                if (Other) {
                    MaxSize = Length = (uint32_t)len;
                    String = (wchar_t*)Other;
                }
            }

            FString(uint32_t len);

            FString operator+(FString other);

            void operator+=(FString other);

            FString substr(size_t off, size_t count = -1);

            size_t find(wchar_t c);

            size_t find(char c);

            size_t find(const wchar_t* c);

            bool contains(wchar_t c);

            bool contains(const wchar_t* c);

            bool starts_with(const wchar_t* c);

            bool ends_with(const wchar_t* c);

            size_t find_first_of(char c);

            size_t find_first_of(wchar_t c);

            wchar_t* c_str();

            operator wchar_t* ();

            void Dealloc();
        private:
            inline void AllocString();
        };

        class FStringUtil {
        public:
            consteval static size_t find_const(const FString s, const wchar_t c) 
            {
                for (uint32_t i = 0; i < s.Length; i++)
                    if (s.String[i] == c)
                        return i;

                return -1;
            }

            template<FString s, size_t off, size_t count = -1>
            consteval static std::array<wchar_t, count == -1 ? s.Length - off : count + 1> substr() 
            {
                std::array<wchar_t, count == -1 ? s.Length - off : count + 1> arr;

                for (size_t i = 0; i < (count == -1 ? (s.Length - off) : count + 1); i++)
                    arr[i] = (s.String + off)[i];

                arr[(count == -1 ? s.Length - off - 1 : count)] = 0;
                return arr;
            }
        };

        class CPPArrayUtil {
        public:
            template<size_t S, std::array<wchar_t, S> s, size_t off, size_t count = -1>
            consteval static std::array<wchar_t, count == -1 ? S - off : count + 1> substr() 
            {
                if (off == FString::npos) 
                    return {};

                std::array<wchar_t, count == -1 ? S - off : count + 1> arr;

                for (size_t i = 0; i < (count == -1 ? (S - off) : count + 1); i++)
                    arr[i] = (s.data() + off)[i];

                arr[(count == -1 ? S - off - 1 : count)] = 0;
                return arr;
            }


            template<size_t S, std::array<wchar_t, S> a>
            consteval static size_t find(const wchar_t c) {
                for (uint32_t i = 0; i < a.size(); i++)
                    if (a[i] == c) 
                        return i;

                return -1;
            }
        };

        inline FString backend;
        class FCurlHttpRequest
        {
        public:
            void** VTable;
            static inline int64_t SetURLIdx;

            void InitializeURLIndex()
            {
                auto GetFunc = uint64_t(*VTable);
                uint32_t URLOffset = 0;

                for (int i = 0; i < 100; i++)
                    if (Tellurium::Patchfinder::CheckBytes<0x48, 0x8D, 0x91>(GetFunc, i))
                    {
                        URLOffset = *(uint32_t*)(__int64(GetFunc) + i + 3);
                        break;
                    }

                if (URLOffset == 0)
                    goto defaultIndex;

                for (int64_t i = 1; i < 0x20; i++)
                {
                    auto func = uint64_t(VTable[i]);

                    for (int j = 0; j < 0x20; j++)
                        if (Tellurium::Patchfinder::CheckBytes<0x48, 0x81, 0xC1>(func, j))
                            if (*(uint32_t*)(func + j + 3) == URLOffset)
                            {
                                FCurlHttpRequest::SetURLIdx = i;
                                return;
                            }
                }
            defaultIndex:
                FCurlHttpRequest::SetURLIdx = 10;
            }

            FString GetURL();

            static inline bool (*ProcessRequestOG)(Tellurium::Unreal::FCurlHttpRequest* _this);
            static inline bool (*ProcessRequestOG__EOS)(Tellurium::Unreal::FCurlHttpRequest* _this);
            void RedirectRequest(bool bEOS);
        };
    }
}