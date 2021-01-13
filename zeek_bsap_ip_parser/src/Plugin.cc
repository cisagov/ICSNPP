// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin 
{
    namespace Zeek_BSAP_IP 
    {
        Plugin plugin;
    }
}

using namespace plugin::Zeek_BSAP_IP;

plugin::Configuration Plugin::Configure()
{
    AddComponent(new ::analyzer::Component("BSAP_IP",::analyzer::BSAP_IP::BSAP_IP_Analyzer::InstantiateAnalyzer));    

    plugin::Configuration config;
    config.name = "Zeek::BSAP_IP";
    config.description = "Bristol Standard Asynchronous Protocol over IP";
    config.version.major = 1;
    config.version.minor = 0;
    
    return config;
}