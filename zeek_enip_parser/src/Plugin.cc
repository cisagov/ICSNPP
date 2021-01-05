// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin { 
    namespace Zeek_ENIP {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_ENIP;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("ENIP_TCP",::analyzer::enip::ENIP_TCP_Analyzer::Instantiate));    
    AddComponent(new ::analyzer::Component("ENIP_UDP",::analyzer::enip::ENIP_UDP_Analyzer::Instantiate));    

    plugin::Configuration config;
    config.name = "Zeek::ENIP";
    config.description = "Ethernet/IP and CIP Protocol analyzer for TCP/UDP";
    
    return config;
    }
