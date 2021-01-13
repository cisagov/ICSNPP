cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek Bsap_serial)
    zeek_plugin_cc(src/Plugin.cc)
    zeek_plugin_cc(src/BSAP_SERIAL.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/bsap_serial.pac src/bsap_serial-analyzer.pac src/bsap_serial-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()