// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ZEEK_PLUGIN_ZEEK_BSAP_IP
#define ZEEK_PLUGIN_ZEEK_BSAP_IP

#include <plugin/Plugin.h>
#include "bsap_ip.h"

namespace plugin 
{
    namespace Zeek_BSAP_IP 
    {
        class Plugin : public ::plugin::Plugin
        {
            protected:
                virtual plugin::Configuration Configure();
        };

        extern Plugin plugin;
    }
}

#endif