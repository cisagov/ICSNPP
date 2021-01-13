##! main.zeek
##!
##! Binpac BSAP_SERIALAnalyzer - Contains the base script-layer functionality for 
##!                              processing events emitted from the analyzer.
##!
##! Author:  Devin Vollmer
##! Contact: devin.vollmer@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module Bsap_serial;

export {
    redef enum Log::ID += { LOG_BSAP_HEADER, 
                            LOG_RDB, 
                            LOG_RDB_EXT, 
                            LOG_UNKNOWN};

    ###############################################################################################
    ###########################  BSAP_Header -> bsap_serial_header.log  ###########################
    ###############################################################################################

    type BSAP_Header: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        id              : conn_id   &log;                   ## The connection's 4-tuple of endpoint addresses/ports.
        ser             : count     &log;                   
        dadd            : count     &log;
        sadd            : count     &log;
        ctl             : count     &log;
        dfun            : string    &log;
        seq             : count     &log;
        sfun            : string    &log;
        nsb             : count     &log;
        type_name       : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_header: event(rec: BSAP_Header);

    ###############################################################################################
    ##############################  BSAP_RDB -> bsap_serial_rdb.log  ##############################
    ###############################################################################################

    type BSAP_RDB: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        func_code       : string    &log;
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_rdb: event(rec: BSAP_RDB);

    ###############################################################################################
    #########################  BSAP_RDB_EXT -> bsap_serial_rdb_ext.log  ###########################
    ###############################################################################################

    type BSAP_RDB_EXT: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        dfun            : string    &log;
        seq             : count     &log;
        sfun            : string    &log;
        nsb             : count     &log;
        extfun          : string    &log;
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_rdb_ext: event(rec: BSAP_RDB_EXT);

    ###############################################################################################
    ##########################  BSAP_UNKNOWN -> bsap_serial_unknown.log  ##########################
    ###############################################################################################

    type BSAP_UNKNOWN: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_unknown: event(rec: BSAP_UNKNOWN);

}

const ports = { 1234/udp , 
             1235/udp
};


redef likely_server_ports += { ports };

###################################################################################################
######## Defines Log Streams for bsap_header.log, bsap_cnv_rdb.log, and bsap_unknown.log  #########
###################################################################################################
event zeek_init() &priority=5
    {
    Log::create_stream(Bsap_serial::LOG_BSAP_HEADER, [$columns=BSAP_Header, $ev=log_bsap_header, $path="bsap_serial_header"]);
    Log::create_stream(Bsap_serial::LOG_RDB, [$columns=BSAP_RDB, $ev=log_bsap_rdb, $path="bsap_serial_rdb"]);
    Log::create_stream(Bsap_serial::LOG_RDB_EXT, [$columns=BSAP_RDB_EXT, $ev=log_bsap_rdb_ext, $path="bsap_serial_rdb_ext"]);
    Log::create_stream(Bsap_serial::LOG_UNKNOWN, [$columns=BSAP_UNKNOWN, $ev=log_bsap_unknown, $path="bsap_serial_unknown"]);

    # TODO: If you're using port-based DPD, uncomment this.
    Analyzer::register_for_ports(Analyzer::ANALYZER_BSAP_SERIAL, ports);
    }


###############################################################################################
############### Defines logging of bsap_local_header event -> bsap_header.log  ################
###############################################################################################
event bsap_local_header(c: connection, SER: count, DFUN: count, SEQ: count, SFUN: count, NSB: count)
    {
    local info: BSAP_Header;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ser = SER;
    info$dfun = app_functions[DFUN];
    info$seq = SEQ;
    info$sfun = app_functions[SFUN];
    info$nsb = NSB;
    info$type_name = "Local Message";
    
    Log::write(Bsap_serial::LOG_BSAP_HEADER, info);
    }   

###############################################################################################
############## Defines logging of bsap_global_header event -> bsap_header.log  ################
###############################################################################################
event bsap_global_header(c: connection, SER: count, DADD: count, SADD: count, CTL: count, DFUN: count,SEQ: count, 
                        SFUN: count, NSB: count)
    {
    local info: BSAP_Header;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$ser = SER;
    info$dadd = DADD;
    info$sadd = SADD;
    info$ctl = CTL;
    info$dfun = app_functions[DFUN];
    info$seq = SEQ;
    info$sfun = app_functions[SFUN];
    info$nsb = NSB;
    info$type_name = "Global Message";
    
    Log::write(Bsap_serial::LOG_BSAP_HEADER, info);
    }   

###############################################################################################
############## Defines logging of bsap_rdb_response event -> bsap_cnv_rdb.log  ################
###############################################################################################
event bsap_rdb_response(c: connection, func_code: count, data: string)
    {
    local info: BSAP_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$func_code = rdb_functions[func_code];
    info$data = data;
    Log::write(Bsap_serial::LOG_RDB, info);
    }   

###############################################################################################
############### Defines logging of bsap_rdb_request event -> bsap_cnv_rdb.log  ################
###############################################################################################
event bsap_rdb_request(c: connection, func_code: count, data: string)
    {
    local info: BSAP_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$func_code = rdb_functions[func_code];
    info$data = data;
    Log::write(Bsap_serial::LOG_RDB, info);
    }

###############################################################################################
############ Defines logging of bsap_rdb_extension event -> bsap_cnv_rdb_ext.log  #############
###############################################################################################
event bsap_rdb_extension(c: connection, DFUN: count, SEQ: count, SFUN: count, NSB: count, XFUN: count, data: string)
    {
    local info: BSAP_RDB_EXT;
    info$ts  = network_time();
    info$uid = c$uid;
    info$dfun = app_functions[DFUN];
    info$seq = SEQ;
    info$sfun = app_functions[SFUN];
    info$nsb = NSB;
    info$extfun = rdb_ext_functions[XFUN];
    info$data = data;
    Log::write(Bsap_serial::LOG_RDB_EXT, info);
    }

###############################################################################################
################# Defines logging of bsap_unknown event -> bsap_unknown.log  ##################
###############################################################################################
event bsap_unknown(c: connection, data: string)
    {

    local info: BSAP_UNKNOWN;
    info$ts  = network_time();
    info$uid = c$uid;
    info$data = data;
    Log::write(Bsap_serial::LOG_UNKNOWN, info);
    }   

