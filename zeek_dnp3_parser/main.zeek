##! main.zeek (Updated)
##!
##! Binpac DNP3 Protocol Analyzer - Contains the base script-layer functionality for processing events 
##!                                 emitted from the analyzer. (Updated from Zeek default DNP3 main.zeek)
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module DNP3;

export {
    redef enum Log::ID += { LOG, 
                            LOG_CONTROL, 
                            LOG_OBJECTS };

    ################################################################################################
    #############################  Default Zeek DNP3 Log -> dnp3.log  ##############################
    ################################################################################################
    type Info: record {
        ts                      : time      &log;             # Timestamp of event
        uid                     : string    &log;             # Zeek unique ID for connection
        id                      : conn_id   &log;             # Zeek connection struct (addresses and ports)
        fc_request              : string    &log &optional;   # DNP3 Function Code in request
        fc_reply                : string    &log &optional;   # DNP3 Function Code in reply
        iin                     : count     &log &optional;   # DNP3 internal indication number
        prefix_value            : count     &optional;        # DNP3 Prefix Value (not logged)
    };
    global log_dnp3: event(rec: Info);

    ###############################################################################################
    ################################  Control -> dnp3_control.log  ################################
    ###############################################################################################
    type Control: record {
        ts                      : time      &log;             # Timestamp of event
        uid                     : string    &log;             # Zeek unique ID for connection
        id                      : conn_id   &log;             # Zeek connection struct (addresses and ports)
        block_type              : string    &optional &log;   # Control_Relay_Output_Block or Pattern_Control_Block
        function_code           : string    &optional &log;   # Function Code (SELECT, OPERATE, RESPONSE)
        index_number            : count     &optional &log;   # Object Index #
        trip_control_code       : string    &optional &log;   # Nul, Close, or Trip
        operation_type          : string    &optional &log;   # Nul, Pulse_On, Pulse_Off, Latch_On, Latch_Off
        execute_count           : count     &optional &log;   # Number of times to execute
        on_time                 : count     &optional &log;   # On Time
        off_time                : count     &optional &log;   # Off Time
        status_code             : string    &optional &log;   # Status Code (see control_block_status_codes)
    };
    global log_control: event(rec: Control);

    ###############################################################################################
    ################################  Objects -> dnp3_objects.log  ################################
    ###############################################################################################
    type Objects: record {
        ts                      : time      &log;             # Timestamp of event
        uid                     : string    &log;             # Zeek unique ID for connection
        id                      : conn_id   &log;             # Zeek connection struct (addresses and ports)
        function_code           : string    &log;             # Function Code (READ or RESPONSE)
        object_type             : string    &log;             # Object type (see dnp3_objects)
        object_count            : count     &log;             # Number of objects
        range_low               : count     &log;             # Range (Low) of object
        range_high              : count     &log;             # Range (High) of object
    };
    global log_objects: event(rec: Objects);
}

redef record connection += {
    dnp3: Info &optional;
    dnp3_control: Control &optional;
};

const ports = { 20000/tcp , 20000/udp };
redef likely_server_ports += { ports };

###################################################################################################
############  Defines Log Streams for dnp3.log, dnp3_control.log, and dnp3_objects.log  ###########
###################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(DNP3::LOG, [$columns=Info, 
                                   $ev=log_dnp3, 
                                   $path="dnp3"]);

    Log::create_stream(DNP3::LOG_CONTROL, [$columns=Control, 
                                           $ev=log_control, 
                                           $path="dnp3_control"]);

    Log::create_stream(DNP3::LOG_OBJECTS, [$columns=Objects, 
                                           $ev=log_objects, 
                                           $path="dnp3_objects"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_DNP3_TCP, ports);
}

###################################################################################################
#########################  Saves prefix_value to DNP3 connection object  ##########################
###################################################################################################
event dnp3_object_prefix(c: connection, 
                         is_orig: bool, 
                         prefix_value: count){

    if ( c?$dnp3 )	
        c$dnp3$prefix_value = prefix_value;
}

###################################################################################################
######################  Saves DNP3 request_header to DNP3 connection object  ######################
###################################################################################################
event dnp3_application_request_header(c: connection, 
                                      is_orig: bool,
                                      application_control: count, 
                                      fc: count){

    if ( ! c?$dnp3 )
        c$dnp3 = [$ts=network_time(), $uid=c$uid, $id=c$id];

    c$dnp3$ts = network_time();
    c$dnp3$fc_request = function_codes[fc];
}

###################################################################################################
###############  Saves response_header and logs DNP3 connection object to dnp3.log  ###############
###################################################################################################
event dnp3_application_response_header(c: connection, 
                                       is_orig: bool, 
                                       application_control: count, 
                                       fc: count, 
                                       iin: count){

    if ( ! c?$dnp3 )
        c$dnp3 = [$ts=network_time(), $uid=c$uid, $id=c$id];

    c$dnp3$ts = network_time();
    c$dnp3$fc_reply = function_codes[fc];
    c$dnp3$iin = iin;
    
    Log::write(LOG, c$dnp3);
}

###################################################################################################
####################  Defines logging of dnp3_crob event -> dnp3_control.log  #####################
###################################################################################################
event dnp3_crob(c: connection, 
                is_orig: bool, 
                control_code: count, 
                count8: count, 
                on_time: count, 
                off_time: count, 
                status_code: count){

    if ( ! c?$dnp3_control )
        c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];

    if ( is_orig )
        c$dnp3_control$function_code = c$dnp3$fc_request;
    else
        c$dnp3_control$function_code = c$dnp3$fc_reply;

    c$dnp3_control$block_type = "Control Relay Output Block";
    c$dnp3_control$index_number = c$dnp3$prefix_value;
    c$dnp3_control$trip_control_code = control_block_trip_code[((control_code & 0xc0)/64)];
    c$dnp3_control$operation_type = control_block_operation_type[(control_code & 0xf)];
    c$dnp3_control$execute_count = count8;
    c$dnp3_control$on_time = on_time;
    c$dnp3_control$off_time = off_time;
    c$dnp3_control$status_code = control_block_status_codes[status_code];
    

    Log::write(LOG_CONTROL, c$dnp3_control);

    if ( !is_orig ){
        delete c$dnp3;
        delete c$dnp3_control;
    }
}

###################################################################################################
#####################  Defines logging of dnp3_pcb event -> dnp3_control.log  #####################
###################################################################################################
event dnp3_pcb(c: connection, 
               is_orig: bool, 
               control_code: count, 
               count8: count, 
               on_time: count, 
               off_time: count, 
               status_code: count){

    if ( ! c?$dnp3_control )
        c$dnp3_control = [$ts=network_time(), $uid=c$uid, $id=c$id];

    if ( is_orig )
        c$dnp3_control$function_code = c$dnp3$fc_request;
    else
        c$dnp3_control$function_code = c$dnp3$fc_reply;

    c$dnp3_control$block_type = "Pattern Control Block";
    c$dnp3_control$index_number = c$dnp3$prefix_value;
    c$dnp3_control$trip_control_code = control_block_trip_code[((control_code & 0xc0)/64)];
    c$dnp3_control$operation_type = control_block_operation_type[(control_code & 0xf)];
    c$dnp3_control$execute_count = count8;
    c$dnp3_control$on_time = on_time;
    c$dnp3_control$off_time = off_time;
    c$dnp3_control$status_code = control_block_status_codes[status_code];
    

    Log::write(LOG_CONTROL, c$dnp3_control);
}

###################################################################################################
################  Defines logging of dnp3_object_header event -> dnp3_objects.log  ################
###################################################################################################
event dnp3_object_header(c: connection, 
                         is_orig: bool, 
                         obj_type: count, 
                         qua_field: count, 
                         number: count, 
                         rf_low: count, 
                         rf_high: count){

    local device_type: string = "";
    device_type = dnp3_objects[obj_type];

    if (device_type == "unknown")
        return;

    local dnp3_object: Objects;

    dnp3_object$ts  = network_time();
    dnp3_object$uid = c$uid;
    dnp3_object$id  = c$id;

    dnp3_object$object_type = device_type;
    
    if ( is_orig ){
        dnp3_object$function_code = c$dnp3$fc_request;
        if (c$dnp3$fc_request != "READ")
            return;
    }
    else{
        dnp3_object$function_code = c$dnp3$fc_reply;
        if (c$dnp3$fc_reply != "RESPONSE")
            return;
        dnp3_object$object_count = number;
        dnp3_object$range_low = rf_low;
        dnp3_object$range_high = rf_high;
    }

    Log::write(LOG_OBJECTS, dnp3_object);
}

###################################################################################################
#############################  Event handling for connection removal  #############################
###################################################################################################
event successful_connection_remove(c: connection) &priority=-5{
    if ( ! c?$dnp3 )
        return;

    delete c$dnp3;
}