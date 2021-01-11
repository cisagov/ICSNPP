##! main.zeek (Updated)
##!
##! Binpac Modbus Protocol Analyzer - Contains the base script-layer functionality for processing events 
##!                                   emitted from the analyzer. (Updated from Zeek default Modbus main.zeek)
##!
##! Authors:  Brett Rasmussen & Stephen Kleinheider
##! Contact:  brett.rasmussen@inl.gov & stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

module Modbus;

export {
    redef enum Log::ID += { LOG,
                            LOG_DETAILED,
                            LOG_MASK_WRITE_REGISTER,
                            LOG_READ_WRITE_MULTIPLE_REGISTERS};

    #########################################################################################################################
    ########################################  Default Zeek Modbus Log -> modbus.log  ########################################
    #########################################################################################################################
    type Info: record {
        ts                      : time      &log;             # Timestamp of event
        uid                     : string    &log;             # Zeek unique ID for connection
        id                      : conn_id   &log;             # Zeek connection struct (addresses and ports)
        func                    : string    &log &optional;   # Modbus Function
        exception               : string    &log &optional;   # Modbus Exception Code 
    };
    global log_modbus: event(rec: Info);

    #########################################################################################################################
    #####################################  Modbus Detailed Log -> modbus_detailed.log  ######################################
    #########################################################################################################################
    type Modbus_Detailed: record {
        ts                      : time              &log;             # Timestamp of event
        uid                     : string            &log;             # Zeek unique ID for connection
        id                      : conn_id           &log;             # Zeek connection struct (addresses and ports)
        unit_id                 : count             &log;             # Modbus unit-id
        func                    : string            &log &optional;   # Modbus Function
        network_direction       : string            &log &optional;   # Message direction (request or response)
        address                 : count             &log &optional;   # Starting address for value(s) field
        quantity                : count             &log &optional;   # Number of addresses/values read or written to
        values                  : string            &log &optional;   # Coils, discrete_inputs, or registers read/written to
    };
    global log_modbus_detailed: event(rec: Modbus_Detailed);

    #########################################################################################################################
    #################################  Mask Write Register Log -> mask_write_register.log  ##################################
    #########################################################################################################################
    type Mask_Write_Register: record {
        ts                      : time              &log;             # Timestamp of event
        uid                     : string            &log;             # Zeek unique ID for connection
        id                      : conn_id           &log;             # Zeek connection struct (addresses and ports)
        unit_id                 : count             &log;             # Modbus unit-id
        func                    : string            &log &optional;   # Modbus Function
        network_direction       : string            &log &optional;   # Message direction (request or response)
        address                 : count             &log &optional;   # Address of the target register
        and_mask                : count             &log &optional;   # Boolean 'and' mask to apply to the target register
        or_mask                 : count             &log &optional;   # Boolean 'or' mask to apply to the target register
    };
    global log_mask_write_register: event(rec: Mask_Write_Register);

    #########################################################################################################################
    #######################  Read Write Multiple Registers Log -> read_write_multiple_registers.log  ########################
    #########################################################################################################################
    type Read_Write_Multiple_Registers: record {
        ts                      : time              &log;             # Timestamp of event
        uid                     : string            &log;             # Zeek unique ID for connection
        id                      : conn_id           &log;             # Zeek connection struct (addresses and ports)
        unit_id                 : count             &log;             # Modbus unit-id
        func                    : string            &log &optional;   # Modbus Function
        network_direction       : string            &log &optional;   # Message direction (request or response)
        write_start_address     : count             &log &optional;   # Starting address of the registers to write to
        write_registers         : ModbusRegisters   &log &optional;   # Register values written
        read_start_address      : count             &log &optional;   # Starting address of the registers to read
        read_quantity           : count             &log &optional;   # Number of registers to read
        read_registers          : ModbusRegisters   &log &optional;   # Register values read
    };
    global log_read_write_multiple_registers: event(rec: Read_Write_Multiple_Registers);
}

redef record connection += {
    modbus: Info &optional;
};

const ports                = { 502/tcp };
redef likely_server_ports += { ports };

const request_str_g:  string = "request";            # Used with Network 'requests'
const response_str_g: string = "response";           # Used with Network 'responses'

#############################################################################################################################
##################################################  Converts 0->F and 1->T  #################################################
#############################################################################################################################
function count_to_bool (count_val: count): string {

    if (count_val > 0)
        return "T";
    else
        return "F";
}

#############################################################################################################################
#######################################  Converts Coil Vector to List of Boolean Values #####################################
#############################################################################################################################
function coils_to_bools_string (coils: ModbusCoils): string {

    local first_iter = T;
    local ret_str = "";

    for ([i] in coils) {
        if (first_iter){
            ret_str = fmt("%s", coils[i]);
            first_iter = F;
        }
        else
            ret_str = fmt("%s,%s", ret_str, coils[i]);
    }

    return ret_str;
}

#############################################################################################################################
######################################  Converts Register Vector to List of Count Values ####################################
#############################################################################################################################
function registers_to_counts_string (registers: ModbusRegisters): string {

    local first_iter = T;
    local ret_str = "";

    for ([i] in registers) {
        if (first_iter) {
            ret_str = fmt("%d", registers[i]);
            first_iter = F;
        }
        else
            ret_str = fmt("%s,%d", ret_str, registers[i]);
    }

    return ret_str;
}
#############################################################################################################################
##############################################  Test for Handled Modbus Functions ###########################################
#############################################################################################################################
function handled_modbus_funct_list (cur_func_str : string): bool {
    if ((cur_func_str == "READ_COILS") ||
        (cur_func_str == "READ_COILS_EXCEPTION") ||
        (cur_func_str == "READ_DISCRETE_INPUTS") ||
        (cur_func_str == "READ_DISCRETE_INPUTS_EXCEPTION") ||
        (cur_func_str == "READ_HOLDING_REGISTERS") ||
        (cur_func_str == "READ_HOLDING_REGISTERS_EXCEPTION") ||
        (cur_func_str == "READ_INPUT_REGISTERS") ||
        (cur_func_str == "READ_INPUT_REGISTERS_EXCEPTION") ||
        (cur_func_str == "READ_FILE_RECORD") ||
        (cur_func_str == "READ_FILE_RECORD_EXCEPTION") ||
        (cur_func_str == "WRITE_SINGLE_COIL") ||
        (cur_func_str == "WRITE_SINGLE_COIL_EXCEPTION") ||
        (cur_func_str == "WRITE_SINGLE_REGISTER") ||
        (cur_func_str == "WRITE_SINGLE_REGISTER_EXCEPTION") ||
        (cur_func_str == "WRITE_MULTIPLE_COILS") ||
        (cur_func_str == "WRITE_MULTIPLE_COILS_EXCEPTION") ||
        (cur_func_str == "WRITE_MULTIPLE_REGISTERS") ||
        (cur_func_str == "WRITE_MULTIPLE_REGISTERS_EXCEPTION") ||
        (cur_func_str == "WRITE_FILE_RECORD") ||
        (cur_func_str == "WRITE_FILE_RECORD_EXCEPTION") ||
        (cur_func_str == "MASK_WRITE_REGISTER") ||
        (cur_func_str == "MASK_WRITE_REGISTER_EXCEPTION")) {
            return T;
    }

    # This function does not yet have a separate message handler
    return F;
}

#############################################################################################################################
#########################  Defines Log Streams for dnp3.log, dnp3_control.log, and dnp3_objects.log  ########################
#############################################################################################################################
event zeek_init() &priority=5 {
    Log::create_stream(Modbus::LOG, [$columns=Info, 
                                     $ev=log_modbus, 
                                     $path="modbus"]);

    Log::create_stream(Modbus::LOG_DETAILED, [$columns=Modbus_Detailed, 
                                              $ev=log_modbus_detailed,
                                              $path="modbus_detailed"]);

    Log::create_stream(Modbus::LOG_MASK_WRITE_REGISTER, [$columns=Mask_Write_Register,
                                                         $ev=log_mask_write_register,
                                                         $path="modbus_mask_write_register"]);

    Log::create_stream(Modbus::LOG_READ_WRITE_MULTIPLE_REGISTERS, [$columns=Read_Write_Multiple_Registers, 
                                                                   $ev=log_read_write_multiple_registers,
                                                                   $path="modbus_read_write_multiple_registers"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_MODBUS, ports);
}

#############################################################################################################################
#####################################  Saves Modbus header to Modbus connection object  #####################################
#############################################################################################################################
event modbus_message(c: connection, 
                     headers: ModbusHeaders, 
                     is_orig: bool) &priority=5 {

    if ( ! c?$modbus )
        c$modbus = [$ts=network_time(), $uid=c$uid, $id=c$id];

    c$modbus$ts      = network_time();
    c$modbus$func    = function_codes[headers$function_code];
}


#############################################################################################################################
###################  Defines logging of modbus_read_discrete_inputs_request event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_discrete_inputs_request(c: connection, 
                                          headers: ModbusHeaders, 
                                          start_address: count, 
                                          quantity: count){

    local read_discrete_inputs_request: Modbus_Detailed;

    read_discrete_inputs_request$ts                 = network_time();
    read_discrete_inputs_request$uid                = c$uid;
    read_discrete_inputs_request$id                 = c$id;

    read_discrete_inputs_request$unit_id            = headers$uid;
    read_discrete_inputs_request$func               = function_codes[headers$function_code];
    read_discrete_inputs_request$network_direction  = request_str_g;
    read_discrete_inputs_request$address            = start_address;
    read_discrete_inputs_request$quantity           = quantity;

    Log::write(LOG_DETAILED, read_discrete_inputs_request);
}

#############################################################################################################################
##################  Defines logging of modbus_read_discrete_inputs_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_discrete_inputs_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           coils: ModbusCoils){

    local read_discrete_inputs_response: Modbus_Detailed;

    read_discrete_inputs_response$ts                = network_time();
    read_discrete_inputs_response$uid               = c$uid;
    read_discrete_inputs_response$id                = c$id;

    read_discrete_inputs_response$unit_id           = headers$uid;
    read_discrete_inputs_response$func              = function_codes[headers$function_code];
    read_discrete_inputs_response$network_direction = response_str_g;
    read_discrete_inputs_response$quantity          = |coils|;
    read_discrete_inputs_response$values            = coils_to_bools_string (coils);

    Log::write(LOG_DETAILED, read_discrete_inputs_response);
}

#############################################################################################################################
########################  Defines logging of modbus_read_coils_request event -> modbus_detailed.log  ########################
#############################################################################################################################
event modbus_read_coils_request(c: connection, 
                                headers: ModbusHeaders, 
                                start_address: count, 
                                quantity: count){
    
    local read_coils_request: Modbus_Detailed;

    read_coils_request$ts                   = network_time();
    read_coils_request$uid                  = c$uid;
    read_coils_request$id                   = c$id;

    read_coils_request$unit_id              = headers$uid;
    read_coils_request$func                 = function_codes[headers$function_code];
    read_coils_request$network_direction    = request_str_g;
    read_coils_request$address              = start_address;
    read_coils_request$quantity             = quantity;

    Log::write(LOG_DETAILED, read_coils_request);
}

#############################################################################################################################
#######################  Defines logging of modbus_read_coils_response event -> modbus_detailed.log  ########################
#############################################################################################################################
event modbus_read_coils_response(c: connection,
                                 headers: ModbusHeaders,
                                 coils: ModbusCoils){
    
    local read_coils_response: Modbus_Detailed;

    read_coils_response$ts                  = network_time();
    read_coils_response$uid                 = c$uid;
    read_coils_response$id                  = c$id;
    read_coils_response$unit_id             = headers$uid;
    read_coils_response$func                = function_codes[headers$function_code];
    read_coils_response$network_direction   = response_str_g;
    read_coils_response$quantity            = |coils|;
    read_coils_response$values              = coils_to_bools_string (coils);

    Log::write(LOG_DETAILED, read_coils_response);
}

#############################################################################################################################
##################  Defines logging of modbus_read_input_registers_request event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_read_input_registers_request(c: connection, 
                                          headers: ModbusHeaders, 
                                          start_address: count, 
                                          quantity: count) {

    local read_input_request: Modbus_Detailed;

    read_input_request$ts                   = network_time();
    read_input_request$uid                  = c$uid;
    read_input_request$id                   = c$id;

    read_input_request$unit_id              = headers$uid;
    read_input_request$func                 = function_codes[headers$function_code];
    read_input_request$network_direction    = request_str_g;
    read_input_request$address              = start_address;
    read_input_request$quantity             = quantity;

    Log::write(LOG_DETAILED, read_input_request);
}

#############################################################################################################################
##################  Defines logging of modbus_read_input_registers_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_read_input_registers_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           registers: ModbusRegisters) {

    local read_input_response: Modbus_Detailed;

    read_input_response$ts                  = network_time();
    read_input_response$uid                 = c$uid;
    read_input_response$id                  = c$id;
    read_input_response$unit_id             = headers$uid;
    read_input_response$func                = function_codes[headers$function_code];
    read_input_response$network_direction   = response_str_g;
    read_input_response$quantity            = |registers|;
    read_input_response$values              = registers_to_counts_string (registers);

    Log::write(LOG_DETAILED, read_input_response);
}

#############################################################################################################################
##################  Defines logging of modbus_read_holding_registers_request event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_read_holding_registers_request(c: connection, 
                                            headers: ModbusHeaders, 
                                            start_address: count, 
                                            quantity: count) {

    local read_holding_request: Modbus_Detailed;

    read_holding_request$ts                 = network_time();
    read_holding_request$uid                = c$uid;
    read_holding_request$id                 = c$id;

    read_holding_request$unit_id            = headers$uid;
    read_holding_request$func               = function_codes[headers$function_code];
    read_holding_request$network_direction  = request_str_g;
    read_holding_request$address            = start_address;
    read_holding_request$quantity           = quantity;

    Log::write(LOG_DETAILED, read_holding_request);
}

#############################################################################################################################
#################  Defines logging of modbus_read_holding_registers_response event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_read_holding_registers_response(c: connection, 
                                             headers: ModbusHeaders, 
                                             registers: ModbusRegisters) {

    local read_holding_reg_response: Modbus_Detailed;

    read_holding_reg_response$ts                = network_time();
    read_holding_reg_response$uid               = c$uid;
    read_holding_reg_response$id                = c$id;

    read_holding_reg_response$unit_id           = headers$uid;
    read_holding_reg_response$func              = function_codes[headers$function_code];
    read_holding_reg_response$network_direction = response_str_g;
    read_holding_reg_response$quantity          = |registers|;
    read_holding_reg_response$values            = registers_to_counts_string (registers);;

    Log::write(LOG_DETAILED, read_holding_reg_response);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_fifo_queue_request event -> modbus_detailed.log  ######################
#############################################################################################################################
event modbus_read_fifo_queue_request(c: connection, 
                                     headers: ModbusHeaders, 
                                     start_address: count) {
    
    local read_fifo_queue_request: Modbus_Detailed;
    
    read_fifo_queue_request$ts                  = network_time();
    read_fifo_queue_request$uid                 = c$uid;
    read_fifo_queue_request$id                  = c$id;

    read_fifo_queue_request$unit_id             = headers$uid;
    read_fifo_queue_request$func                = function_codes[headers$function_code];
    read_fifo_queue_request$network_direction   = request_str_g;
    read_fifo_queue_request$address             = start_address;

    Log::write(LOG_DETAILED, read_fifo_queue_request);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_fifo_queue_response event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_read_fifo_queue_response(c: connection, 
                                      headers: ModbusHeaders, 
                                      fifos: ModbusRegisters) {

    local read_fifo_queue_response: Modbus_Detailed;

    read_fifo_queue_response$ts                 = network_time();
    read_fifo_queue_response$uid                = c$uid;
    read_fifo_queue_response$id                 = c$id;
    
    read_fifo_queue_response$unit_id            = headers$uid;
    read_fifo_queue_response$func               = function_codes[headers$function_code];
    read_fifo_queue_response$network_direction  = response_str_g;
    read_fifo_queue_response$quantity           = |fifos|;
    read_fifo_queue_response$values             = registers_to_counts_string (fifos);

    Log::write(LOG_DETAILED, read_fifo_queue_response);
}

#############################################################################################################################
#####################  Defines logging of modbus_write_single_coil_request event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_write_single_coil_request(c: connection, 
                                       headers: ModbusHeaders, 
                                       address: count, 
                                       value: bool) {
    
    local write_single_coil_request: Modbus_Detailed;
    
    write_single_coil_request$ts                = network_time();
    write_single_coil_request$uid               = c$uid;
    write_single_coil_request$id                = c$id;

    write_single_coil_request$unit_id           = headers$uid;
    write_single_coil_request$func              = function_codes[headers$function_code];
    write_single_coil_request$network_direction = request_str_g;
    write_single_coil_request$address           = address;
    write_single_coil_request$quantity          = 1;
    write_single_coil_request$values            = fmt("%s", value);

    Log::write(LOG_DETAILED, write_single_coil_request);
}

#############################################################################################################################
####################  Defines logging of modbus_write_single_coil_response event -> modbus_detailed.log  ####################
#############################################################################################################################
event modbus_write_single_coil_response(c: connection, 
                                        headers: ModbusHeaders, 
                                        address: count, 
                                        value: bool) {
    
    local write_single_coil_response: Modbus_Detailed;
    
    write_single_coil_response$ts                   = network_time();
    write_single_coil_response$uid                  = c$uid;
    write_single_coil_response$id                   = c$id;

    write_single_coil_response$unit_id              = headers$uid;
    write_single_coil_response$func                 = function_codes[headers$function_code];
    write_single_coil_response$network_direction    = response_str_g;
    write_single_coil_response$address              = address;
    write_single_coil_response$quantity             = 1;
    write_single_coil_response$values               = fmt("%s", value);

    Log::write(LOG_DETAILED, write_single_coil_response);
}

#############################################################################################################################
###################  Defines logging of modbus_write_single_register_request event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_write_single_register_request(c: connection, 
                                           headers: ModbusHeaders, 
                                           address: count, 
                                           value: count) {

    local write_single_register_request: Modbus_Detailed;

    write_single_register_request$ts                = network_time();
    write_single_register_request$uid               = c$uid;
    write_single_register_request$id                = c$id;

    write_single_register_request$unit_id           = headers$uid;
    write_single_register_request$func              = function_codes[headers$function_code];
    write_single_register_request$network_direction = request_str_g;
    write_single_register_request$address           = address;
    write_single_register_request$quantity          = 1;
    write_single_register_request$values            = fmt("%d", value);

    Log::write(LOG_DETAILED, write_single_register_request);
}

#############################################################################################################################
##################  Defines logging of modbus_write_single_register_response event -> modbus_detailed.log  ##################
#############################################################################################################################
event modbus_write_single_register_response(c: connection, 
                                            headers: ModbusHeaders, 
                                            address: count, 
                                            value: count) {
    
    local write_single_register_response: Modbus_Detailed;

    write_single_register_response$ts                   = network_time();
    write_single_register_response$uid                  = c$uid;
    write_single_register_response$id                   = c$id;

    write_single_register_response$unit_id              = headers$uid;
    write_single_register_response$func                 = function_codes[headers$function_code];
    write_single_register_response$network_direction    = response_str_g;
    write_single_register_response$address              = address;
    write_single_register_response$quantity             = 1;
    write_single_register_response$values               = fmt("%d", value);

    Log::write(LOG_DETAILED, write_single_register_response);
}

#############################################################################################################################
###################  Defines logging of modbus_write_multiple_coils_request event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_write_multiple_coils_request(c: connection, 
                                          headers: ModbusHeaders, 
                                          start_address: count, 
                                          coils: ModbusCoils) {

    local write_multiple_coils_request: Modbus_Detailed;

    write_multiple_coils_request$ts                 = network_time();
    write_multiple_coils_request$uid                = c$uid;
    write_multiple_coils_request$id                 = c$id;

    write_multiple_coils_request$unit_id            = headers$uid;
    write_multiple_coils_request$func               = function_codes[headers$function_code];
    write_multiple_coils_request$network_direction  = request_str_g;
    write_multiple_coils_request$address            = start_address;
    write_multiple_coils_request$quantity           = |coils|;
    write_multiple_coils_request$values             = coils_to_bools_string (coils);;
    
    Log::write(LOG_DETAILED, write_multiple_coils_request);
}

#############################################################################################################################
##################  Defines logging of modbus_write_multiple_coils_response event -> modbus_detailed.log  ###################
#############################################################################################################################
event modbus_write_multiple_coils_response(c: connection, 
                                           headers: ModbusHeaders, 
                                           start_address: count, 
                                           quantity: count) {

    local write_multiple_coils_response: Modbus_Detailed;

    write_multiple_coils_response$ts                = network_time();
    write_multiple_coils_response$uid               = c$uid;
    write_multiple_coils_response$id                = c$id;

    write_multiple_coils_response$unit_id           = headers$uid;
    write_multiple_coils_response$func              = function_codes[headers$function_code];
    write_multiple_coils_response$network_direction = response_str_g;
    write_multiple_coils_response$address           = start_address;
    write_multiple_coils_response$quantity          = quantity;

    Log::write(LOG_DETAILED, write_multiple_coils_response);
}

#############################################################################################################################
#################  Defines logging of modbus_write_multiple_registers_request event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_write_multiple_registers_request(c: connection, 
                                              headers: ModbusHeaders, 
                                              start_address: count, 
                                              registers: ModbusRegisters) {

    local write_multiple_registers_request: Modbus_Detailed;

    write_multiple_registers_request$ts                 = network_time();
    write_multiple_registers_request$uid                = c$uid;
    write_multiple_registers_request$id                 = c$id;

    write_multiple_registers_request$unit_id            = headers$uid;
    write_multiple_registers_request$func               = function_codes[headers$function_code];
    write_multiple_registers_request$network_direction  = request_str_g;
    write_multiple_registers_request$address            = start_address;
    write_multiple_registers_request$quantity           = |registers|;
    write_multiple_registers_request$values             = registers_to_counts_string (registers);;

    Log::write(LOG_DETAILED, write_multiple_registers_request);
}

#############################################################################################################################
#################  Defines logging of modbus_write_multiple_registers_request event -> modbus_detailed.log  #################
#############################################################################################################################
event modbus_write_multiple_registers_response(c: connection, 
                                               headers: ModbusHeaders, 
                                               start_address: count, 
                                               quantity: count) {

    local write_multiple_registers_response: Modbus_Detailed;
        
    write_multiple_registers_response$ts                = network_time();
    write_multiple_registers_response$uid               = c$uid;
    write_multiple_registers_response$id                = c$id;

    write_multiple_registers_response$unit_id           = headers$uid;
    write_multiple_registers_response$func              = function_codes[headers$function_code];
    write_multiple_registers_response$network_direction = response_str_g;
    write_multiple_registers_response$address           = start_address;
    write_multiple_registers_response$quantity          = quantity;

    Log::write(LOG_DETAILED, write_multiple_registers_response);
}

#############################################################################################################################
####  Defines logging of modbus_read_write_multiple_registers_request event -> modbus_read_write_multiple_registers.log  ####
#############################################################################################################################
event modbus_read_write_multiple_registers_request(c: connection, 
                                                   headers: ModbusHeaders, 
                                                   read_start_address: count, 
                                                   read_quantity: count, 
                                                   write_start_address: count, 
                                                   write_registers: ModbusRegisters) {

    local read_write_multiple_registers_request: Read_Write_Multiple_Registers;

    read_write_multiple_registers_request$ts                   = network_time();
    read_write_multiple_registers_request$uid                  = c$uid;
    read_write_multiple_registers_request$id                   = c$id;

    read_write_multiple_registers_request$unit_id              = headers$uid;
    read_write_multiple_registers_request$func                 = function_codes[headers$function_code];
    read_write_multiple_registers_request$network_direction    = request_str_g;
    read_write_multiple_registers_request$read_start_address   = read_start_address;
    read_write_multiple_registers_request$read_quantity        = read_quantity;
    read_write_multiple_registers_request$write_start_address  = write_start_address;
    read_write_multiple_registers_request$write_registers      = write_registers;

    Log::write(Modbus::LOG_READ_WRITE_MULTIPLE_REGISTERS, read_write_multiple_registers_request);
}

#############################################################################################################################
####  Defines logging of modbus_read_write_multiple_registers_response event -> modbus_read_write_multiple_registers.log  ###
#############################################################################################################################
event modbus_read_write_multiple_registers_response(c: connection, 
                                                    headers: ModbusHeaders, 
                                                    written_registers: ModbusRegisters) {
    
    local read_write_multiple_registers_response: Read_Write_Multiple_Registers;

    read_write_multiple_registers_response$ts                   = network_time();
    read_write_multiple_registers_response$uid                  = c$uid;
    read_write_multiple_registers_response$id                   = c$id;

    read_write_multiple_registers_response$unit_id              = headers$uid;
    read_write_multiple_registers_response$func                 = function_codes[headers$function_code];
    read_write_multiple_registers_response$network_direction    = response_str_g;
    read_write_multiple_registers_response$read_registers       = written_registers;

    Log::write(Modbus::LOG_READ_WRITE_MULTIPLE_REGISTERS, read_write_multiple_registers_response);
}

#############################################################################################################################
#####################  Defines logging of modbus_read_file_record_request event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_read_file_record_request(c: connection, 
                                      headers: ModbusHeaders) {

    local read_file_record_request: Modbus_Detailed;

    read_file_record_request$ts                 = network_time();
    read_file_record_request$uid                = c$uid;
    read_file_record_request$id                 = c$id;
    read_file_record_request$unit_id            = headers$uid;
    read_file_record_request$func               = function_codes[headers$function_code];
    read_file_record_request$network_direction  = request_str_g;

    Log::write(LOG_DETAILED, read_file_record_request);
}

#############################################################################################################################
####################  Defines logging of modbus_read_file_record_response event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_read_file_record_response(c: connection, 
                                       headers: ModbusHeaders) {  

    local read_file_record_response: Modbus_Detailed; 

    read_file_record_response$ts                = network_time();
    read_file_record_response$uid               = c$uid;
    read_file_record_response$id                = c$id;

    read_file_record_response$unit_id           = headers$uid;
    read_file_record_response$func              = function_codes[headers$function_code];
    read_file_record_response$network_direction = response_str_g;

    Log::write(LOG_DETAILED, read_file_record_response);
}

#############################################################################################################################
####################  Defines logging of modbus_write_file_record_request event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_write_file_record_request(c: connection, 
                                       headers: ModbusHeaders){  

    local write_file_record_request: Modbus_Detailed;

    write_file_record_request$ts                = network_time();
    write_file_record_request$uid               = c$uid;
    write_file_record_request$id                = c$id;

    write_file_record_request$unit_id           = headers$uid;
    write_file_record_request$func              = function_codes[headers$function_code];
    write_file_record_request$network_direction = request_str_g;

    Log::write(LOG_DETAILED, write_file_record_request);
}

#############################################################################################################################
###################  Defines logging of modbus_write_file_record_response event -> modbus_detailed.log  #####################
#############################################################################################################################
event modbus_write_file_record_response(c: connection, 
                                        headers: ModbusHeaders) {

    local write_file_record_response: Modbus_Detailed;

    write_file_record_response$ts                   = network_time();
    write_file_record_response$uid                  = c$uid;
    write_file_record_response$id                   = c$id;
    
    write_file_record_response$unit_id              = headers$uid;
    write_file_record_response$func                 = function_codes[headers$function_code];
    write_file_record_response$network_direction    = response_str_g;

    Log::write(LOG_DETAILED, write_file_record_response);
}

#############################################################################################################################
#################  Defines logging of modbus_mask_write_register_request event -> mask_write_register.log  ##################
#############################################################################################################################
event modbus_mask_write_register_request(c: connection, 
                                         headers: ModbusHeaders, 
                                         address: count, 
                                         and_mask: count, 
                                         or_mask: count) {

    local mask_write_register_request: Mask_Write_Register;
 
    mask_write_register_request$ts                  = network_time();
    mask_write_register_request$uid                 = c$uid;
    mask_write_register_request$id                  = c$id;

    mask_write_register_request$unit_id             = headers$uid;
    mask_write_register_request$func                = function_codes[headers$function_code];
    mask_write_register_request$network_direction   = request_str_g;
    mask_write_register_request$address             = address;
    mask_write_register_request$and_mask            = and_mask;
    mask_write_register_request$or_mask             = or_mask;

    Log::write(Modbus::LOG_MASK_WRITE_REGISTER, mask_write_register_request);
}

#############################################################################################################################
#################  Defines logging of modbus_mask_write_register_response event -> mask_write_register.log  #################
#############################################################################################################################
event modbus_mask_write_register_response(c: connection, 
                                          headers: ModbusHeaders, 
                                          address: count,
                                          and_mask: count, 
                                          or_mask: count) {
  
    local mask_write_register_response: Mask_Write_Register;

    mask_write_register_response$ts                 = network_time();
    mask_write_register_response$uid                = c$uid;
    mask_write_register_response$id                 = c$id;

    mask_write_register_response$unit_id            = headers$uid;
    mask_write_register_response$func               = function_codes[headers$function_code];
    mask_write_register_response$network_direction  = response_str_g;
    mask_write_register_response$address            = address;
    mask_write_register_response$and_mask           = and_mask;
    mask_write_register_response$or_mask            = or_mask;

    Log::write(Modbus::LOG_MASK_WRITE_REGISTER, mask_write_register_response);
}
#############################################################################################################################
######################  Logs Modbus connection object to modbus.log and possibly modbus_detailed.log  #######################
#############################################################################################################################
event modbus_message(c: connection, 
                     headers: ModbusHeaders, 
                     is_orig: bool) &priority=-5 {

    local modbus_detailed_rec: Modbus_Detailed;

    if ( ! is_orig && ( headers$function_code <= 0x81 || headers$function_code >= 0x98 )) {
          Log::write(LOG, c$modbus);
    }

    if (( headers$function_code < 0x81 || headers$function_code > 0x98 )) {
        if (is_orig)
            modbus_detailed_rec$network_direction = request_str_g;
        else
            modbus_detailed_rec$network_direction = response_str_g;

        if ( !handled_modbus_funct_list (c$modbus$func)) {
            modbus_detailed_rec$ts        = c$modbus$ts;
            modbus_detailed_rec$uid       = c$modbus$uid;
            modbus_detailed_rec$id        = c$modbus$id;
            modbus_detailed_rec$func      = c$modbus$func;

            Log::write(LOG_DETAILED, modbus_detailed_rec);
        }
    }
}

#############################################################################################################################
#####################################  Saves exception code to Modbus connection object  ####################################
#############################################################################################################################
event modbus_exception(c: connection, 
                       headers: ModbusHeaders, 
                       code: count) &priority=5 {

    c$modbus$exception = exception_codes[code];
}

#############################################################################################################################
######################  Defines logging of modbus_exception event -> modbus.log & modbus_detailed.log  ######################
#############################################################################################################################
event modbus_exception(c: connection, 
                       headers: ModbusHeaders, 
                       code: count) &priority=-5 {
    
    local exception_detailed: Modbus_Detailed;

    exception_detailed$ts                   = network_time();
    exception_detailed$uid                  = c$uid;
    exception_detailed$id                   = c$id;
    exception_detailed$func                 = c$modbus$func;
    exception_detailed$network_direction    = response_str_g;
    exception_detailed$values               = c$modbus$exception;

    Log::write(LOG_DETAILED, exception_detailed);
    Log::write(LOG, c$modbus);

    delete c$modbus$exception;
}



