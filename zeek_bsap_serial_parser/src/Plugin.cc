// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin 
{
    namespace Zeek_BSAP_SERIAL
    {
        Plugin plugin;
    }
}

using namespace plugin::Zeek_BSAP_SERIAL;

plugin::Configuration Plugin::Configure()
{
    AddComponent(new ::analyzer::Component("BSAP_SERIAL",::analyzer::BSAP_SERIAL::BSAP_SERIAL_Analyzer::InstantiateAnalyzer));    

    plugin::Configuration config;
    config.name = "Zeek::BSAP_SERIAL";
    config.description = "Bristol Standard Asynchronous Protocol for Serial->Ethernet";
    config.version.major = 1;
    config.version.minor = 0;
    
    return config;
}