cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek Bacnet)
    zeek_plugin_cc(src/BACNET.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/bacnet.pac src/bacnet-analyzer.pac src/bacnet-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()