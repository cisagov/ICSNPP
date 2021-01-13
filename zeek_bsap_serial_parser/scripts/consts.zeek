##"Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved."
## consts.zeek
##
## Binpac BSAP (BSAP) Analyzer - Defines BSAP Constants for main.zeek
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov

module Bsap_serial;

export {
    const UINT32_MAX = 0xFFFFFFFF;

    #############################################################
    #########           BSAP APPFUNC CODES              #########
    #############################################################
    const app_functions = {
        [0x03] = "PEI_PC",
        [0xA0] = "RDB",
        [0xA1] = "RDB_EXTENSION",
        ## more to can be implemented from const.pac
    } &default = function(n: count): string {return fmt("Unknown APP Func-0x%02x", n); };

    ###############################################################################################
    #########################        BSAP RDB Function codes             ##########################
    ###############################################################################################
    const rdb_functions = {
        [0x00] = "READ_SIGNAL_BY_ADDRESS",
        [0x02] = "READ_LOGICAL_BY_ADDRESS",
        [0x04] = "READ_SIGNAL_BY_NAME",
        [0x06] = "READ_LOGICAL_BY_NAME",
        [0x0C] = "READ_SIGNAL_BY_LIST_START",
        [0x0D] = "READ_SIGNAL_BY_LIST_CONTINUE",
        [0x0E] = "READ_LOGICAL_BY_LIST_START",
        [0x0F] = "READ_LOGICAL_BY_LIST_CONTINUE",

        [0x50] = "RSP_READ_SIGNAL_BY_ADDRESS",                  #func code + 0x50 this is for formatting log file only not specified in documents
        [0x52] = "RSP_READ_LOGICAL_BY_ADDRESS",                 #func code + 0x50 this is for formatting log file only not specified in documents
        [0x54] = "RSP_READ_SIGNAL_BY_NAME",                     #func code + 0x50 this is for formatting log file only not specified in documents
        [0x56] = "RSP_READ_LOGICAL_BY_NAME",                    #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5C] = "RSP_READ_SIGNAL_BY_LIST_START",               #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5D] = "RSP_READ_SIGNAL_BY_LIST_CONTINUE",            #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5E] = "RSP_READ_LOGICAL_BY_LIST_START",              #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5F] = "RSP_READ_LOGICAL_BY_LIST_CONTINUE",           #func code + 0x50 this is for formatting log file only not specified in documents


        [0x80] = "WRITE_SIGNAL_BY_ADDRESS",
        [0x84] = "WRITE_SIGNAL_BY_NAME",
        [0x8C] = "WRITE_SIGNAL_BY_LIST_START",
        [0x8D] = "WRITE_SIGNAL_BY_LIST_CONTINUE",


        [0xD0] = "RSP_WRITE_SIGNAL_BY_ADDRESS",                 #func code + 0x50 this is for formatting log file only not specified in documents
        [0xD4] = "RSP_WRITE_SIGNAL_BY_NAME",                    #func code + 0x50 this is for formatting log file only not specified in documents
        [0xDC] = "RSP_WRITE_SIGNAL_BY_LIST_START",              #func code + 0x50 this is for formatting log file only not specified in documents
        [0xDD] = "RSP_WRITE_SIGNAL_BY_LIST_CONTINUE",           #func code + 0x50 this is for formatting log file only not specified in documents
    } &default = function(n: count): string {return fmt("Unknown RDB Func-0x%02x", n); };

    const rdb_ext_functions = {
        [0x0101] = "RESET SYSTEM",
        [0x0102] = "DIAGNOSTICS RESET",
        [0x0201] = "READ DATE AND TIME",
        [0x0202] = "READ DATE",
        [0x0203] = "READ TIME",
        [0x0281] = "WRITE DATE AND TIME",
        [0x0400] = "CHANGE LOCAL NODE ADDR",
    } &default = function(n: count): string {return fmt("Unknown RDB Func-0x%02x", n); };
}
