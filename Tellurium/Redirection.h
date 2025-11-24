#pragma once
#include "pch.h"
#include "url.h"

namespace Tellurium 
{
    namespace Redirection 
    {
        bool ShouldRedirect(URL& uri);
    }
}