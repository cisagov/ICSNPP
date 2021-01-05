// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin { 
    namespace Zeek_BACNET {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_BACNET;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("BACNET",::analyzer::BACNET::BACNET_Analyzer::InstantiateAnalyzer));    

    plugin::Configuration config;
    config.name = "Zeek::BACnet";
    config.description = "BACnet Protocol analyzer";
    
    return config;
    }
