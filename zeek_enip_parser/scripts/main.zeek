##! main.zeek
##!
##! Binpac Ethernet/IP (ENIP) Analyzer - Contains the base script-layer functionality for 
##!                                      processing events emitted from the analyzer.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module ENIP;

export{
    redef enum Log::ID += { LOG_ENIP, 
                            LOG_CIP, 
                            LOG_CIP_IO, 
                            LOG_CIP_IDENTITY };
    
    ###############################################################################################
    ##################################  ENIP_Header -> enip.log  ##################################
    ###############################################################################################
    type ENIP_Header: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        enip_command            : string    &log;   # Ethernet/IP Command (see enip_commands)
        length                  : count     &log;   # Length of ENIP data following header
        session_handle          : string    &log;   # Sesesion identifier
        enip_status             : string    &log;   # Status code (see enip_statuses)
        sender_context          : string    &log;   # Sender context
        options                 : string    &log;   # Options flags
    };
    global log_enip: event(rec: ENIP_Header);

    ###############################################################################################
    ###################################  CIP_Header -> cip.log  ###################################
    ###############################################################################################
    type CIP_Header: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        cip_sequence_count      : count     &log;   # CIP sequence number for transport
        direction               : string    &log;   # Request or Response
        cip_service             : string    &log;   # CIP service type (see cip_services)
        cip_status              : string    &log;   # CIP status code (see cip_statuses)
        class_id                : string    &log;   # CIP Request Path - Class ID
        class_name              : string    &log;   # CIP Request Path - Class Name (see cip_classes)
        instance_id             : string    &log;   # CIP Request Path - Instance ID
        attribute_id            : string    &log;   # CIP Request Path - Attribute ID
        data_id                 : string    &log;   # CIP Request Path - Data ID
        other_id                : string    &log;   # CIP Request Path - Other ID
    };
    global log_cip: event(rec: CIP_Header);

    ###############################################################################################
    ##################################  CIP_IO_Log -> cip_io.log  #################################
    ###############################################################################################
    type CIP_IO_Log: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        connection_id           : string    &log;   # CIP Connection Identifier 
        sequence_number         : count     &log;   # CIP Sequence Number with Connection
        data_length             : count     &log;   # Length of io_data field
        io_data                 : string    &log;   # CIP IO Data
    };
    global log_cip_io: event(rec: CIP_IO_Log);

    ###############################################################################################
    #########################  CIP_Identity_Item_Log -> cip_identity.log  #########################
    ###############################################################################################
    type CIP_Identity_Item_Log: record {
        ts                      : time      &log;   # Timestamp of event
        uid                     : string    &log;   # Zeek unique ID for connection
        id                      : conn_id   &log;   # Zeek connection struct (addresses and ports)
        encapsulation_version   : count     &log;   # Encapsulation protocol version supported
        socket_address          : addr      &log;   # Socket address IP address
        socket_port             : count     &log;   # Socket address port number
        vendor_id               : count     &log;   # Vendor ID
        vendor_name             : string    &log;   # Name of Vendor (see cip_vendors)
        device_type_id          : count     &log;   # Device type ID
        device_type_name        : string    &log;   # Name of device type (see cip_device_types)
        product_code            : count     &log;   # Product code assigned to device
        revision                : string    &log;   # Device revision (major.minor)
        device_status           : string    &log;   # Current status of device (see cip_statuses)
        serial_number           : string    &log;   # Serial number of device
        product_name            : string    &log;   # Human readable description of device
        device_state            : string    &log;   # Current state of the device
    };
    global log_cip_identity: event(rec: CIP_Identity_Item_Log);
}

# Defines ENIP/CIP ports
const ports = {
    2222/udp,
    44818/tcp,
    44818/udp,
};

# Defines ENIP/CIP UDP ports
const udp_ports = {
    2222/udp,
    44818/udp,
};

# Defines ENIP/CIP TCP ports
const tcp_ports = {
    44818/tcp,
};
redef likely_server_ports += { ports };

###################################################################################################
################  Defines Log Streams for enip.log, cip.log, and cip_identity.log  ################
###################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(ENIP::LOG_ENIP, [$columns=ENIP_Header, 
                                        $ev=log_enip, 
                                        $path="enip"]);

    Log::create_stream(ENIP::LOG_CIP, [$columns=CIP_Header, 
                                       $ev=log_cip, 
                                       $path="cip"]);

    Log::create_stream(ENIP::LOG_CIP_IO, [$columns=CIP_IO_Log, 
                                          $ev=log_cip_io, 
                                          $path="cip_io"]);

    Log::create_stream(ENIP::LOG_CIP_IDENTITY, [$columns=CIP_Identity_Item_Log, 
                                                $ev=log_cip_identity, 
                                                $path="cip_identity"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_TCP, tcp_ports);
    Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_UDP, udp_ports);
}

###################################################################################################
#######################  Defines logging of enip_header event -> enip.log  ########################
###################################################################################################
event enip_header(c: connection, 
                  command: count, 
                  length: count,
                  session_handle: count, 
                  status: count, 
                  sender_context: string, 
                  options: count) {
    
    local enip_item: ENIP_Header;
    enip_item$ts  = network_time();
    enip_item$uid = c$uid;
    enip_item$id  = c$id;

    enip_item$enip_command = enip_commands[command];
    enip_item$length = length;
    enip_item$session_handle = fmt("0x%08x", session_handle);
    enip_item$enip_status = enip_statuses[status];
    enip_item$sender_context = fmt("0x%s", bytestring_to_hexstr(sender_context));
    enip_item$options = fmt("0x%08x", options);

    Log::write(LOG_ENIP, enip_item);
}

###################################################################################################
########################  Defines logging of cip_header event -> cip.log  #########################
###################################################################################################
event cip_header(c: connection, 
                 cip_sequence_count: count, 
                 service: count, 
                 response: bool, 
                 status: count, class_id: count, 
                 instance_id: count, 
                 attribute_id: count, 
                 data_id: string, 
                 other_id: string){
    
    local cip_header_item: CIP_Header;
    cip_header_item$ts  = network_time();
    cip_header_item$uid = c$uid;
    cip_header_item$id  = c$id;

    if (cip_sequence_count != 0)
        cip_header_item$cip_sequence_count = cip_sequence_count;
    
    cip_header_item$cip_service = cip_services[service];
    
    if(response){
        cip_header_item$direction = "response";
        cip_header_item$cip_status = cip_statuses[status];
    }else{
        cip_header_item$direction = "request";
        
        if(class_id != UINT32_MAX){
            cip_header_item$class_id = fmt("0x%x",class_id);
            cip_header_item$class_name = cip_classes[class_id];
        }
        
        if(instance_id != UINT32_MAX)
            cip_header_item$instance_id = fmt("0x%x",instance_id);
        
        if(attribute_id != UINT32_MAX)
            cip_header_item$attribute_id = fmt("0x%x",attribute_id);
        
        if(data_id != "")
            cip_header_item$data_id = data_id;
        
        if(other_id != "")
            cip_header_item$other_id = other_id;
    }

    Log::write(LOG_CIP, cip_header_item);
}

###################################################################################################
#########################  Defines logging of cip_io event -> cip_io.log  #########################
###################################################################################################
event cip_io(c: connection, 
             connection_identifier: count, 
             sequence_number: count, 
             data_length: count, 
             data: string){

    local cip_io_item: CIP_IO_Log;
    cip_io_item$ts  = network_time();
    cip_io_item$uid = c$uid;
    cip_io_item$id  = c$id;
    cip_io_item$connection_id = fmt("0x%08x", connection_identifier);;
    cip_io_item$sequence_number = sequence_number;
    cip_io_item$data_length = data_length;
    cip_io_item$io_data = data;

    Log::write(LOG_CIP_IO, cip_io_item);
}

###################################################################################################
###################  Defines logging of cip_identity event -> cip_identity.log  ###################
###################################################################################################
event cip_identity(c: connection, encapsulation_version: count,
                   socket_address: count,
                   socket_port: count,
                   vendor_id: count,
                   device_type: count,
                   product_code: count,
                   revision_major: count,
                   revision_minor: count,
                   status: count,
                   serial_number: count,
                   product_name: string,
                   state: count ){
    
    local cip_identity_item: CIP_Identity_Item_Log;
    cip_identity_item$ts  = network_time();
    cip_identity_item$uid = c$uid;
    cip_identity_item$id  = c$id;
    cip_identity_item$encapsulation_version = encapsulation_version;
    cip_identity_item$socket_address = count_to_v4_addr(socket_address);
    cip_identity_item$socket_port = socket_port;
    cip_identity_item$vendor_id = vendor_id;
    cip_identity_item$vendor_name = cip_vendors[vendor_id];
    cip_identity_item$device_type_id = device_type;
    cip_identity_item$device_type_name = cip_device_types[device_type];
    cip_identity_item$product_code = product_code;
    cip_identity_item$revision = fmt("%d.%d", revision_major, revision_minor);
    cip_identity_item$device_status = fmt("0x%04x", status);
    cip_identity_item$serial_number = fmt("0x%08x", serial_number);
    cip_identity_item$product_name = product_name;
    cip_identity_item$device_state = fmt("0x%04x", state);
    Log::write(LOG_CIP_IDENTITY, cip_identity_item);
}