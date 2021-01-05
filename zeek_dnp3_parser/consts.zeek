##! consts.zeek (Updated)
##!
##! Binpac DNP3 Protocol Analyzer - Defines DNP3 Constants for main.zeek
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module DNP3;

export {
    ###############################################################################################
    ####################################  DNP3 Function Codes  ####################################
    ###############################################################################################

    const function_codes = {
        # Requests.
        [0x00] = "CONFIRM",
        [0x01] = "READ",
        [0x02] = "WRITE",
        [0x03] = "SELECT",
        [0x04] = "OPERATE",
        [0x05] = "DIRECT_OPERATE",
        [0x06] = "DIRECT_OPERATE_NR",
        [0x07] = "IMMED_FREEZE",
        [0x08] = "IMMED_FREEZE_NR",
        [0x09] = "FREEZE_CLEAR",
        [0x0a] = "FREEZE_CLEAR_NR",
        [0x0b] = "FREEZE_AT_TIME",
        [0x0c] = "FREEZE_AT_TIME_NR",
        [0x0d] = "COLD_RESTART",
        [0x0e] = "WARM_RESTART",
        [0x0f] = "INITIALIZE_DATA",
        [0x10] = "INITIALIZE_APPL",
        [0x11] = "START_APPL",
        [0x12] = "STOP_APPL",
        [0x13] = "SAVE_CONFIG",
        [0x14] = "ENABLE_UNSOLICITED",
        [0x15] = "DISABLE_UNSOLICITED",
        [0x16] = "ASSIGN_CLASS",
        [0x17] = "DELAY_MEASURE",
        [0x18] = "RECORD_CURRENT_TIME",
        [0x19] = "OPEN_FILE",
        [0x1a] = "CLOSE_FILE",
        [0x1b] = "DELETE_FILE",
        [0x1c] = "GET_FILE_INFO",
        [0x1d] = "AUTHENTICATE_FILE",
        [0x1e] = "ABORT_FILE",
        [0x1f] = "ACTIVATE_CONFIG",
        [0x20] = "AUTHENTICATE_REQ",
        [0x21] = "AUTHENTICATE_REQ_NR",

        # Responses.
        [0x81] = "RESPONSE",
        [0x82] = "UNSOLICITED_RESPONSE",
        [0x83] = "AUTHENTICATE_RESP",
    } &default=function(i: count):string { return fmt("unknown-%x", i); } &redef;

    ###############################################################################################
    #################################  Control Block Trip Codes  ##################################
    ###############################################################################################
    const control_block_trip_code = {
        [0x0] = "Nul",
        [0x1] = "Close",
        [0x2] = "Trip",
    } &default=function(i: count):string { return fmt("unknown-%x", i); } &redef;

    ###############################################################################################
    ###############################  Control Block Operation Types  ###############################
    ###############################################################################################
    const control_block_operation_type = {
        [0x0] = "Nul",
        [0x1] = "Pulse On",
        [0x2] = "Pulse Off",
        [0x3] = "Latch On",
        [0x4] = "Latch Off",
    } &default=function(i: count):string { return fmt("unknown-%x", i); } &redef;

    ###############################################################################################
    ################################  Control Block Status Codes  #################################
    ###############################################################################################
    const control_block_status_codes = {
        [0x00] = "Success",
        [0x01] = "Timeout",
        [0x02] = "No Select",
        [0x03] = "Format Error",
        [0x04] = "Not Supported",
        [0x05] = "Latch Off",
        [0x06] = "Already Active",
        [0x07] = "Hardware Error",
        [0x08] = "Too Many Objs",
        [0x09] = "Not Authorized",
        [0x0a] = "Automation Inhibit",
        [0x0b] = "Processing Limited",
        [0x0c] = "Out of Range",
        [0x7e] = "Non Participating",
        [0x7f] = "Undefined",
    } &default=function(i: count):string { return fmt("unknown-%x", i); } &redef;

    ###############################################################################################
    #######################################  DNP3 Objects  ########################################
    ###############################################################################################
    const dnp3_objects = {
        [0x0100] = "Binary Input Default Variation",
        [0x0101] = "Single-bit Binary Input",
        [0x0102] = "Binary Input With Status",
        [0x0200] = "Binary Input Change Default Variation",
        [0x0201] = "Binary Input Change Without Time",
        [0x0202] = "Binary Input Change With Time",
        [0x0203] = "Binary Input Change With Relative Time",
        [0x0300] = "Double-bit Input Default Variation",
        [0x0301] = "Double-bit Input No Flags",
        [0x0302] = "Double-bit Input With Status",
        [0x0400] = "Double-bit Input Change Default Variation",
        [0x0401] = "Double-bit Input Change Without Time",
        [0x0402] = "Double-bit Input Change With Time",
        [0x0403] = "Double-bit Input Change With Relative Time",
        [0x0A00] = "Binary Output Default Variation",
        [0x0A01] = "Binary Output",
        [0x0A02] = "Binary Output Status",
        [0x0B00] = "Binary Output Change Default Variation",
        [0x0B01] = "Binary Output Change Without Time",
        [0x0B02] = "Binary Output Change With Time",
        [0x1400] = "Binary Counter Default Variation",
        [0x1401] = "32-Bit Binary Counter",
        [0x1402] = "16-Bit Binary Counter",
        [0x1403] = "32-Bit Delta Counter",
        [0x1404] = "16-Bit Delta Counter",
        [0x1405] = "32-Bit Binary Counter Without Flag",
        [0x1406] = "16-Bit Binary Counter Without Flag",
        [0x1407] = "32-Bit Delta Counter Without Flag",
        [0x1408] = "16-Bit Delta Counter Without Flag",
        [0x1500] = "Frozen Binary Counter Default Variation",
        [0x1501] = "32-Bit Frozen Counter",
        [0x1502] = "16-Bit Frozen Counter",
        [0x1503] = "32-Bit Frozen Delta Counter",
        [0x1504] = "16-Bit Frozen Delta Counter",
        [0x1505] = "32-Bit Frozen Counter w/ Time of Freeze",
        [0x1506] = "16-Bit Frozen Counter w/ Time of Freeze",
        [0x1507] = "32-Bit Frozen Delta Counter w/ Time of Freeze",
        [0x1508] = "16-Bit Frozen Delta Counter w/ Time of Freeze",
        [0x1509] = "32-Bit Frozen Counter Without Flag",
        [0x150A] = "16-Bit Frozen Counter Without Flag",
        [0x150B] = "32-Bit Frozen Delta Counter Without Flag",
        [0x150C] = "16-Bit Frozen Delta Counter Without Flag",
        [0x1600] = "Counter Change Event Default Variation",
        [0x1601] = "32-Bit Counter Change Event w/o Time",
        [0x1602] = "16-Bit Counter Change Event w/o Time",
        [0x1603] = "32-Bit Delta Counter Change Event w/o Time",
        [0x1604] = "16-Bit Delta Counter Change Event w/o Time",
        [0x1605] = "32-Bit Counter Change Event with Time",
        [0x1606] = "16-Bit Counter Change Event with Time",
        [0x1607] = "32-Bit Delta Counter Change Event with Time",
        [0x1608] = "16-Bit Delta Counter Change Event with Time",
        [0x1700] = "Frozen Binary Counter Change Event Default Variation",
        [0x1701] = "32-Bit Frozen Counter Change Event",
        [0x1702] = "16-Bit Frozen Counter Change Event",
        [0x1703] = "32-Bit Frozen Delta Counter Change Event",
        [0x1704] = "16-Bit Frozen Delta Counter Change Event",
        [0x1705] = "32-Bit Frozen Counter Change Event w/ Time of Freeze",
        [0x1706] = "16-Bit Frozen Counter Change Event w/ Time of Freeze",
        [0x1707] = "32-Bit Frozen Delta Counter Change Event w/ Time of Freeze",
        [0x1708] = "16-Bit Frozen Delta Counter Change Event w/ Time of Freeze",
        [0x1E00] = "Analog Input Default Variation",
        [0x1E01] = "32-Bit Analog Input",
        [0x1E02] = "16-Bit Analog Input",
        [0x1E03] = "32-Bit Analog Input Without Flag",
        [0x1E04] = "16-Bit Analog Input Without Flag",
        [0x1E05] = "32-Bit Floating Point Input",
        [0x1E06] = "64-Bit Floating Point Input",
        [0x1F01] = "32-Bit Frozen Analog Input",
        [0x1F02] = "16-Bit Frozen Analog Input",
        [0x1F03] = "32-Bit Frozen Analog Input w/ Time of Freeze",
        [0x1F04] = "16-Bit Frozen Analog Input w/ Time of Freeze",
        [0x1F05] = "32-Bit Frozen Analog Input Without Flag",
        [0x1F06] = "16-Bit Frozen Analog Input Without Flag",
        [0x1F07] = "32-Bit Frozen Floating Point Input",
        [0x1F08] = "64-Bit Frozen Floating Point Input",
        [0x2000] = "Analog Input Change Default Variation",
        [0x2001] = "32-Bit Analog Change Event w/o Time",
        [0x2002] = "16-Bit Analog Change Event w/o Time",
        [0x2003] = "32-Bit Analog Change Event w/ Time",
        [0x2004] = "16-Bit Analog Change Event w/ Time",
        [0x2005] = "32-Bit Floating Point Change Event w/o Time",
        [0x2006] = "64-Bit Floating Point Change Event w/o Time",
        [0x2007] = "32-Bit Floating Point Change Event w/ Time",
        [0x2008] = "64-Bit Floating Point Change Event w/ Time",
        [0x2101] = "32-Bit Frozen Analog Event w/o Time",
        [0x2102] = "16-Bit Frozen Analog Event w/o Time",
        [0x2103] = "32-Bit Frozen Analog Event w/ Time",
        [0x2104] = "16-Bit Frozen Analog Event w/ Time",
        [0x2105] = "32-Bit Floating Point Frozen Change Event w/o Time",
        [0x2106] = "64-Bit Floating Point Frozen Change Event w/o Time",
        [0x2107] = "32-Bit Floating Point Frozen Change Event w/ Time",
        [0x2108] = "64-Bit Floating Point Frozen Change Event w/ Time",
        [0x2800] = "Analog Output Default Variation",
        [0x2801] = "32-Bit Analog Output Status",
        [0x2802] = "16-Bit Analog Output Status",
        [0x2803] = "32-Bit Floating Point Output Status",
        [0x2804] = "64-Bit Floating Point Output Status",
        [0x2901] = "32-Bit Analog Output Block",
        [0x2902] = "16-Bit Analog Output Block",
        [0x2903] = "32-Bit Floating Point Output Block",
        [0x2904] = "64-Bit Floating Point Output Block",
        [0x2A00] = "Analog Output Event Default Variation",
        [0x2A01] = "32-Bit Analog Output Event w/o Time",
        [0x2A02] = "16-Bit Analog Output Event w/o Time",
        [0x2A03] = "32-Bit Analog Output Event w/ Time",
        [0x2A04] = "16-Bit Analog Output Event w/ Time",
        [0x2A05] = "32-Bit Floating Point Output Event w/o Time",
        [0x2A06] = "64-Bit Floating Point Output Event w/o Time",
        [0x2A07] = "32-Bit Floating Point Output Event w/ Time",
        [0x2A08] = "64-Bit Floating Point Output Event w/ Time",
        [0x3C01] = "Class 0 Data",
        [0x3C02] = "Class 1 Data",
        [0x3C03] = "Class 2 Data",
        [0x3C04] = "Class 3 Data",
    } &default=function(i: count):string { return fmt("unknown"); } &redef;

}


