// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ZEEK_PLUGIN_ZEEK_ENIP
#define ZEEK_PLUGIN_ZEEK_ENIP

#include <plugin/Plugin.h>
#include "ENIP.h"

namespace plugin {
    namespace Zeek_ENIP {
        class Plugin : public ::plugin::Plugin {
            protected:
                virtual plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif