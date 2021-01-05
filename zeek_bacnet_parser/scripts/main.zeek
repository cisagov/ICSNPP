##! main.zeek
##!
##! Binpac BACnet Protocol Analyzer - Contains the base script-layer functionality for processing
##!                                   events emitted from the analyzer.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module Bacnet;

export {
    redef enum Log::ID += { LOG_BACNET, 
                            LOG_BACNET_DISCOVERY, 
                            LOG_BACNET_PROPERTY};

    ###############################################################################################
    ################################  BACnet_Header -> bacnet.log  ################################
    ###############################################################################################
    type BACnet_Header: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        bvlc_function           : string    &log;   # BVLC function (see bvlc_functions)
        pdu_type                : string    &log;   # APDU type (see apdu_types)
        pdu_service             : string    &log;   # APDU service (see unconfirmed_service_choice and confirmed_service_choice)
        invoke_id               : count     &log;   # Invoke ID
        result_code             : string    &log;   # See (abort_reasons, reject_reasons, and error_codes)
    };
    
    global log_bacnet: event(rec: BACnet_Header);

    ###############################################################################################
    ##################  Who-Is, I-Am, Who-Has, & I-Have -> bacnet_discovery.log  ##################
    ###############################################################################################
    type BACnet_Discovery: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        pdu_service             : string    &log;   # who-is, i-am, who-has, or i-have
        object_type             : string    &log;   # BACnetObjectIdentifier object (see object_types)
        instance_number         : count     &log;   # BACnetObjectIdentifier instance number
        vendor                  : string    &log;   # Vendor Name (i-am and i-have requests)
        range                   : string    &log;   # Specify range of devices to return (in who-is and who-has requests)
        object_name             : string    &log;   # Object name searching for (who-has) or responding with (i-have)
    };
    global log_bacnet_discovery: event(rec: BACnet_Discovery);

    ###############################################################################################
    ###################  Read-Property & Write-Property -> bacnet_property.log  ###################
    ###############################################################################################
    type BACnet_Property: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        pdu_service             : string    &log;   # read-property-request/ack, write-property-request
        object_type             : string    &log;   # BACnetObjectIdentifier object (see object_types)
        instance_number         : count     &log;   # BACnetObjectIdentifier instance number
        property                : string    &log;   # Property type (see property_identifiers)
        array_index             : count     &log;   # Array index of property
        value                   : string    &log;   # Value of property
    };
    global log_bacnet_property: event(rec: BACnet_Property);

}

## Defines BACnet Ports
const ports = { 47808/udp };
redef likely_server_ports += { ports };

###################################################################################################
#######  Defines Log Streams for bacnet.log, bacnet_discovery.log, and bacnet_property.log  #######
###################################################################################################
event zeek_init() &priority=5{
    Log::create_stream(Bacnet::LOG_BACNET, [$columns=BACnet_Header, 
                                            $ev=log_bacnet, 
                                            $path="bacnet"]);

    Log::create_stream(Bacnet::LOG_BACNET_DISCOVERY, [$columns=BACnet_Discovery, 
                                                      $ev=log_bacnet_discovery, 
                                                      $path="bacnet_discovery"]);

    Log::create_stream(Bacnet::LOG_BACNET_PROPERTY, [$columns=BACnet_Property, 
                                                     $ev=log_bacnet_property, 
                                                     $path="bacnet_property"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_BACNET, ports);
}

###################################################################################################
#####################  Defines logging of bacnet_header event -> bacnet.log  ######################
###################################################################################################
event bacnet_header(c: connection, 
                    bvlc_function: count, 
                    pdu_type: count, 
                    pdu_service: count, 
                    invoke_id: count, 
                    result_code: count){

    local bacnet_log: BACnet_Header;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    bacnet_log$bvlc_function = bvlc_functions[bvlc_function];

    if (bvlc_function == 0)
        bacnet_log$result_code = bvlc_results[result_code];

    if(pdu_type != -1){
        bacnet_log$pdu_type = apdu_types[pdu_type];

        if (pdu_type != 1)
            bacnet_log$invoke_id = invoke_id;
    }

    switch(pdu_type){
        case 5:
            bacnet_log$result_code = error_codes[result_code];
            fallthrough;
        case 0:
            fallthrough;
        case 2:
            fallthrough;
        case 3:
            fallthrough;
        case 4:
            bacnet_log$pdu_service = confirmed_service_choice[pdu_service];
            break;
        case 1:
            bacnet_log$pdu_service = unconfirmed_service_choice[pdu_service];
            break;
        case 6:
            bacnet_log$result_code = reject_reasons[result_code];
            break;
        case 7:
            bacnet_log$result_code = abort_reasons[result_code];
            break;
        default:
            break;
    }

    Log::write(LOG_BACNET, bacnet_log);
}

###################################################################################################
################  Defines logging of bacnet_who_is event -> bacnet_discovery.log  #################
###################################################################################################
event bacnet_who_is(c: connection, 
                    low_limit: count, 
                    high_limit: count){

    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    bacnet_discovery$pdu_service = "who-is";

    if(low_limit == UINT32_MAX)
        bacnet_discovery$range = "All";
    else
        bacnet_discovery$range = fmt("%d-%d", low_limit, high_limit);
    
    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
#################  Defines logging of bacnet_i_am event -> bacnet_discovery.log  ##################
###################################################################################################
event bacnet_i_am(c: connection, 
                  object_type: count, 
                  instance_number: count, 
                  max_apdu: count, 
                  segmentation: count, 
                  vendor_id: count){

    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    bacnet_discovery$pdu_service = "i-am";
    bacnet_discovery$object_type = object_types[object_type]; 
    bacnet_discovery$instance_number = instance_number;
    bacnet_discovery$vendor = vendors[vendor_id];

    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
################  Defines logging of bacnet_who_has event -> bacnet_discovery.log  ################
###################################################################################################
event bacnet_who_has(c: connection, 
                     low_limit: count, 
                     high_limit: count, 
                     object_type: count, 
                     instance_number: count, 
                     object_name: string){

    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    bacnet_discovery$pdu_service = "who-has";
    
    if(instance_number != UINT32_MAX){
        bacnet_discovery$object_type = object_types[object_type]; 
        bacnet_discovery$instance_number = instance_number;
    }

    if(object_name == "")
        bacnet_discovery$object_name = "N/A";
    else
        bacnet_discovery$object_name = object_name;

    if(low_limit == UINT32_MAX)
        bacnet_discovery$range = "All";
    else
        bacnet_discovery$range = fmt("%d-%d", low_limit, high_limit);
    
    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
################  Defines logging of bacnet_i_have event -> bacnet_discovery.log  #################
###################################################################################################
event bacnet_i_have(c: connection, 
                    device_object_type: count, 
                    device_instance_num: count, 
                    object_object_type: count, 
                    object_instance_num: count, 
                    object_name: string){

    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    bacnet_discovery$pdu_service = "i-have";
    bacnet_discovery$object_type = object_types[object_object_type]; 
    bacnet_discovery$instance_number = object_instance_num;
    bacnet_discovery$object_name = object_name;

    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
#############  Defines logging of bacnet_read_property event -> bacnet_property.log  ##############
###################################################################################################
event bacnet_read_property(c: connection, 
                           pdu_service: string, 
                           object_type: count, 
                           instance_number: count, 
                           property_identifier: count, 
                           property_array_index: count){

    local bacnet_property: BACnet_Property;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    bacnet_property$pdu_service = pdu_service;
    bacnet_property$object_type = object_types[object_type]; 
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];
    
    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;
    
    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
###########  Defines logging of bacnet_read_property_ack event -> bacnet_property.log  ############
###################################################################################################
event bacnet_read_property_ack(c: connection, 
                               pdu_service: string, 
                               object_type: count, 
                               instance_number: count, 
                               property_identifier: count, 
                               property_array_index: count, 
                               property_value: string){

    local bacnet_property: BACnet_Property;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    bacnet_property$pdu_service = pdu_service;
    bacnet_property$object_type = object_types[object_type]; 
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];
    
    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;
    
    if( property_identifier == 117)
        bacnet_property$value = bacnet_units[to_count(property_value)];
    else if( property_identifier == 79 )
        bacnet_property$value = object_types[to_count(property_value)];
    else
        bacnet_property$value = property_value;
    
    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
#############  Defines logging of bacnet_write_property event -> bacnet_property.log  #############
###################################################################################################
event bacnet_write_property(c: connection,
                            object_type: count, 
                            instance_number: count, 
                            property_identifier: count, 
                            property_array_index: count, 
                            priority: count, 
                            property_value: string){

    local bacnet_property: BACnet_Property;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    bacnet_property$pdu_service = "write-property";
    bacnet_property$object_type = object_types[object_type]; 
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];
    
    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;
    
    if( property_identifier == 117)
        bacnet_property$value = bacnet_units[to_count(property_value)];
    else if( property_identifier == 79 )
        bacnet_property$value = object_types[to_count(property_value)];
    else
        bacnet_property$value = property_value;
    
    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
#############  Defines logging of bacnet_property_error event -> bacnet_property.log  #############
###################################################################################################
event bacnet_property_error(c: connection, 
                            pdu_type: count, 
                            pdu_service: count, 
                            result_code: count){

    local bacnet_property: BACnet_Property;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    bacnet_property$pdu_service = "ERROR: " + confirmed_service_choice[pdu_service];
    bacnet_property$object_type = error_codes[result_code];

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}