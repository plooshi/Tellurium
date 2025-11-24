#pragma once
#include "pch.h"
#include "Unreal.h"

namespace Tellurium
{
    class URL
    {
    public:
        using StrType = Unreal::FString;
        StrType Protocol, Seperator, Domain, Port, Path, Query;

        __forceinline URL(StrType& url)
        {
            __stosb((uint8_t*)this, 0, sizeof(URL));

            auto ProtoEnd = url.find(':');
            Protocol = url.substr(0, ProtoEnd);

            auto ProtoSize = (url[ProtoEnd + 1] == '/' && url[ProtoEnd + 2] == '/') ? 3 : 1;
            Seperator = url.substr(ProtoEnd, ProtoSize);

            auto DomainAndPortStart = url.substr(ProtoEnd + ProtoSize);
            auto PathEnd = DomainAndPortStart.find_first_of('/');
            auto DomainAndPort = DomainAndPortStart.substr(0, PathEnd);
            auto PathStart = DomainAndPortStart.substr(PathEnd);
            DomainAndPortStart.Dealloc();

            auto PortOff = DomainAndPort.find_first_of(':');

            Domain = DomainAndPort.substr(0, PortOff);
            if (PortOff != StrType::npos) Port = DomainAndPort.substr(PortOff);
            DomainAndPort.Dealloc();

            auto QueryOff = PathStart.find_first_of('?');
            Path = PathStart.substr(0, QueryOff);

            if (QueryOff != StrType::npos) 
                Query = PathStart.substr(QueryOff);

            PathStart.Dealloc();
        }

        __forceinline URL& SetHost(StrType host)
        {
            auto ProtoEnd = host.find(':');
            Protocol = host.substr(0, ProtoEnd);

            auto ProtoSize = (host[ProtoEnd + 1] == '/' && host[ProtoEnd + 2] == '/') ? 3 : 1;
            Seperator.Dealloc();
            Seperator = host.substr(ProtoEnd, ProtoSize);

            auto DomainAndPortStart = host.substr(ProtoEnd + ProtoSize);
            auto PathEnd = DomainAndPortStart.find_first_of('/');
            auto DomainAndPort = DomainAndPortStart.substr(0, PathEnd);
            DomainAndPortStart.Dealloc();

            auto PortOff = DomainAndPort.find_first_of(':');

            Domain.Dealloc();
            Domain = DomainAndPort.substr(0, PortOff);

            if (PortOff != StrType::npos) 
            {
                Port.Dealloc();
                Port = DomainAndPort.substr(PortOff);
            }

            DomainAndPort.Dealloc();
            return *this;
        }

        template <StrType host>
        __forceinline URL& SetHost()
        {
            constexpr auto ProtoEnd = Unreal::FStringUtil::find_const(host, ':');
            Protocol.Dealloc();
            constexpr static auto ProtocolS = Unreal::FStringUtil::substr<host, 0, ProtoEnd>();
            constexpr StrType ProtocolV = ProtocolS.data();
            Protocol = ProtocolV;

            constexpr auto ProtoSize = (host.String[ProtoEnd + 1] == '/' && host.String[ProtoEnd + 2] == '/') ? 3 : 1;
            Seperator.Dealloc();
            constexpr static auto SeperatorS = Unreal::FStringUtil::substr<host, ProtoEnd, ProtoSize>();
            constexpr StrType SeperatorV = SeperatorS.data();
            Seperator = SeperatorV;

            constexpr auto DomainAndPortStart = Unreal::FStringUtil::substr<host, ProtoEnd + ProtoSize>();
            constexpr auto PathEnd = Unreal::CPPArrayUtil::find<DomainAndPortStart.size(), DomainAndPortStart>('/');
            constexpr auto DomainAndPort = Unreal::CPPArrayUtil::substr<DomainAndPortStart.size(), DomainAndPortStart, 0, PathEnd>();
            constexpr auto PortOff = Unreal::CPPArrayUtil::find<DomainAndPort.size(), DomainAndPort>(':');
            Domain.Dealloc();

            constexpr static auto DomainS = Unreal::CPPArrayUtil::substr<DomainAndPort.size(), DomainAndPort, 0, PortOff>();
            constexpr StrType DomainV = DomainS.data();
            Domain = DomainV;

            if (PortOff != StrType::npos) 
            {
                Port.Dealloc();
                constexpr static auto PortS = Unreal::CPPArrayUtil::substr<DomainAndPort.size(), DomainAndPort, PortOff>();
                constexpr StrType PortV = PortS.data();
                Port = PortV;
            }

            return *this;
        }

        __forceinline StrType GetUrl()
        {
            auto OutStr = StrType((Protocol.Length - 1) + (Seperator.Length - 1) + (Domain.Length - 1) + (Port.String ? Port.Length - 1 : 0) + (Path.Length - 1) + (Query.String ? Query.Length - 1 : 0));

            __movsb(PBYTE(OutStr.String), (const PBYTE)Protocol.String, Protocol.Length * 2);
            __movsb(PBYTE(OutStr.String + wcslen(OutStr.String)), (const PBYTE)Seperator.String, Seperator.Length * 2);
            __movsb(PBYTE(OutStr.String + wcslen(OutStr.String)), (const PBYTE)Domain.String, Domain.Length * 2);
            if (Port.String) __movsb(PBYTE(OutStr.String + wcslen(OutStr.String)), (const PBYTE)Port.String, Port.Length * 2);
            __movsb(PBYTE(OutStr.String + wcslen(OutStr.String)), (const PBYTE)Path.String, Path.Length * 2);
            if (Query.String) __movsb(PBYTE(OutStr.String + wcslen(OutStr.String)), (const PBYTE)Query.String, Query.Length * 2);

            return OutStr;
        }

        __forceinline operator StrType()
        {
            return GetUrl();
        }

        void DeallocPathQuery() 
        {
            Path.Dealloc();
            Query.Dealloc();
        }

        void Dealloc() 
        {
            Protocol.Dealloc();
            Seperator.Dealloc();
            Domain.Dealloc();
            Port.Dealloc();
            Path.Dealloc();
            Query.Dealloc();
        }
    };

}
#ifdef __clang__
#define __URL_SetHost(url, host) url.SetHost(host)
#else
#define __URL_SetHost(url, host) url.SetHost<host>()
#endif