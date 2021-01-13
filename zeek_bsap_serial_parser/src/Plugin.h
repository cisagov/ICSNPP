// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ZEEK_PLUGIN_ZEEK_BSAP_SERIAL
#define ZEEK_PLUGIN_ZEEK_BSAP_SERIAL

#include <plugin/Plugin.h>
#include "BSAP_SERIAL.h"

namespace plugin 
{
    namespace Zeek_BSAP_SERIAL
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