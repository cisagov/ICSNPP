cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek Bsap_ip)
    zeek_plugin_cc(src/Plugin.cc)
    zeek_plugin_cc(src/bsap_ip.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/bsap_ip.pac src/bsap_ip-analyzer.pac src/bsap_ip-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()