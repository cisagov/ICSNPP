##! consts.zeek
##!
##! Binpac BSAP (BSAP) Analyzer - Defines BSAP Constants for main.zeek
##!
##! Author:  Devin Vollmer
##! Contact: devin.vollmer@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module Bsap_ip;

export {
    const UINT32_MAX = 0xFFFFFFFF;

    #############################################################
    #########            BSAP MESSAGE TYPE              #########
    #########  These are values that are not in         #########
    #########  bsap programmers reference guide.        #########
    #########  They do make sense with data flow        #########
    #########  from plc. These were implemented         #########
    #########  by BYU-I students.                       #########
    #############################################################
    const msg_types = {
        [0x0000] = "POLL",
        [0x0001] = "RESPONSECNT",
        [0x0005] = "RESPONSE",
        [0x0006] = "REQUEST",
    } &default = function(n: count): string {return fmt("Unknown Message Type-0x%02x", n); };


    #############################################################
    #########           BSAP APPFUNC CODES              #########
    #########  The application function codes are       ######### 
    #########  referenced in the bsap reference         ######### 
    #########  guide. Looking into the dll for          ######### 
    #########  openBSI it looks like the RDB func       ######### 
    #########  codes are the only ones that are         ######### 
    #########  implemented for BSAP_IP.                 #########
    #############################################################
    const app_functions = {
        [0xA0] = "RDB",
    } &default = function(n: count): string {return fmt("Unknown APP Func-0x%02x", n); };

    ###############################################################################################
    #########################        BSAP RDB Command codes              ##########################
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
}
