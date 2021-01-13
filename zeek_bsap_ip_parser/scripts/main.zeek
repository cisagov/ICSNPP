##! main.zeek
##!
##! Binpac BSAP (BSAP_IP) Analyzer - Contains the base script-layer functionality for 
##!                                  processing events emitted from the analyzer.
##!                                  For use with BSAP over IP communication.
##!
##!
##! Author:  Devin Vollmer
##! Contact: devin.vollmer@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved."

module Bsap_ip;

export {
    redef enum Log::ID += { LOG_BSAP_IP, 
                            LOG_RDB, 
                            LOG_UNKNOWN };

    ###############################################################################################
    #############################  BSAPIP_Header -> bsap_ip_header.log  ###########################
    ###############################################################################################
    type BSAPIP_Header: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        id              : conn_id   &log;                   ## The connection's 4-tuple of endpoint addresses/ports.
        num_msg         : count     &log;                   ## Number of function calls in message packet
        type_name       : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsapip_header: event(rec: BSAPIP_Header);

    ###############################################################################################
    ################################  BSAP_RDB -> bsap_ip_rdb.log  ################################
    ###############################################################################################
    type BSAP_RDB: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        header_size     : count     &log;                   ## The connection's 4-tuple of endpoint addresses/ports.
        mes_seq         : count     &log;
        res_seq         : count     &log;
        data_len        : count     &log;
        sequence        : count     &log;
        app_func_code   : string    &log;
        node_status     : count     &log;
        func_code       : string    &log;
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsap_rdb_ip: event(rec: BSAP_RDB);

    ###############################################################################################
    ############################  BSAPIP_UNKNOWN -> bsap_ip_unknown.log  ##########################
    ###############################################################################################
    type BSAPIP_UNKNOWN: record {
        ts              : time      &log;                   ## Timestamp for when the event happened.
        uid             : string    &log;                   ## Unique ID for the connection.
        data            : string    &log;
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_bsapip_unknown: event(rec: BSAPIP_UNKNOWN);
}

#port 1234,1235 are default port numbers used by BSAPIPDRV
const ports = { 1234/udp, 
                1235/udp
};

redef likely_server_ports += { ports };

###################################################################################################
########### Defines Log Streams for bsapip_header.log, bsapip_rdb.log, bsapip_unknown  ############
###################################################################################################
event zeek_init() &priority=5
    {
    Log::create_stream(Bsap_ip::LOG_BSAP_IP, [$columns=BSAPIP_Header, $ev=log_bsapip_header, $path="bsap_ip_header"]);
    Log::create_stream(Bsap_ip::LOG_RDB, [$columns=BSAP_RDB, $ev=log_bsap_rdb_ip, $path="bsap_ip_rdb"]);
    Log::create_stream(Bsap_ip::LOG_UNKNOWN, [$columns=BSAPIP_UNKNOWN, $ev=log_bsapip_unknown, $path="bsap_ip_unknown"]);

    # TODO: If you're using port-based DPD, uncomment this.
    Analyzer::register_for_ports(Analyzer::ANALYZER_BSAP_IP, ports);
    }

###############################################################################################
################ Defines logging of bsapip_header event -> bsapip_header.log  #################
###############################################################################################
event bsapip_header(c: connection, is_orig: bool, id: count, Num_Messages: count, 
                    Message_Func: count)
    {
    local info: BSAPIP_Header;
    info$ts  = network_time();
    info$uid = c$uid;
    info$id  = c$id;
    info$num_msg = Num_Messages;
    info$type_name = msg_types[Message_Func];
    #info$mes_seq = message_seq;
    #info$res_seq = response_seq;
    #info$data_len = data_length;
    
    Log::write(Bsap_ip::LOG_BSAP_IP, info);
    }   

###############################################################################################
############### Defines logging of bsapip_rdb_response event -> bsap_rdb.log  #################
###############################################################################################
event bsapip_rdb_response(c: connection, message_seq: count, response_seq: count, data_length: count, 
                    header_size: count, sequence: count, func_code: count, resp_status: count, data: string)
    {
    local info: BSAP_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$mes_seq = message_seq;
    info$res_seq = response_seq;
    info$data_len = data_length;
    info$header_size = header_size;
    info$sequence = sequence;
    info$app_func_code = "RDB";
    info$node_status = func_code;
    info$func_code = rdb_functions[func_code];
    #info$num_data = nme;
    info$data = data;
    Log::write(Bsap_ip::LOG_RDB, info);
    }   

###############################################################################################
################ Defines logging of bsapip_rdb_request event -> bsap_rdb.log  #################
###############################################################################################
event bsapip_rdb_request(c: connection, response_seq: count, message_seq: count, 
                        node_status: count, func_code: count, data: string)
    {
    local info: BSAP_RDB;
    info$ts  = network_time();
    info$uid = c$uid;
    info$mes_seq = message_seq;
    info$res_seq = response_seq;
    info$app_func_code = "RDB";
    info$node_status = node_status;
    info$func_code = rdb_functions[func_code];
    info$data = data;
    Log::write(Bsap_ip::LOG_RDB, info);
    }

###############################################################################################
################# Defines logging of bsap_unknown event -> bsap_unknown.log  ##################
###############################################################################################
event bsapip_unknown(c: connection, data: string)
    {
    local info: BSAPIP_UNKNOWN;
    info$ts  = network_time();
    info$uid = c$uid;
    info$data = data;
    Log::write(Bsap_ip::LOG_UNKNOWN, info);
    }   