## enip-protocol.pac
##
## Binpac Ethernet/IP (ENIP) Analyzer - Defines Protocol Message Formats
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%include consts.pac

###################################################################################################
#####################################  ZEEK CONNECTION DATA  ######################################
###################################################################################################

## --------------------------------------------ENIP-PDU--------------------------------------------
## Message Description:
##      Main Ethernet/IP PDU
## Message Format:
##      - header:                   ENIP_Header         -> See ENIP_Header
##      - body:                     variable            -> ENIP_Originator or ENIP_Target
## Protocol Parsing:
##      Starts protocol parsing by getting Ethernet/IP header and passes processing to either
##      ENIP_Originator or ENIP_Target depending on is_orig value.
## ------------------------------------------------------------------------------------------------
type ENIP_PDU(is_orig: bool) = record {
    command:    uint16;
    proto: case command of {
        2                     -> udp_pdu:                  CIP_IO;
        default               -> tcp_pdu:                  ENIP_TCP(is_orig, command);
    };
} &byteorder=littleendian;

type ENIP_TCP(is_orig: bool, command: uint16) = record {
    header                  : ENIP_Header(command);
    body                    : case is_orig of {
        true                -> originator:              ENIP_Originator(command);
        false               -> target:                  ENIP_Target(command);
    };
} &byteorder=littleendian;

## ---------------------------------------------CIP-IO---------------------------------------------
## Message Description:
##      CIP IO uses a different format than other CIP packets
## Message Format:
##      - sequenced_address_type:     uint16                    -> Always 0x8002
##      - sequenced_address_length:   uint16                    -> Always 8
##      - sequenced_address_item:     Sequenced_Address_Item    -> See Sequenced_Address_Item
##      - connected_data_type:        uint16                    -> Always 0x00B1
##      - connected_data_length:      uint16                    -> Length of connected_data
##      - connected_data_item:        variable                  -> CIP IO data
## Protocol Parsing:
##      Starts protocol parsing by getting Ethernet/IP header and passes processing to either
##      ENIP_Originator or ENIP_Target depending on is_orig value.
## ------------------------------------------------------------------------------------------------
type CIP_IO = record {
    sequenced_address_type:     uint16; # Always 0x8002
    sequenced_address_length:   uint16; # Always 8
    sequenced_address_item:     Sequenced_Address_Item;
    connected_data_type:        uint16; # Always 0x00B1
    connected_data_length:      uint16;
    connected_data_item:        bytestring &length=connected_data_length;
} &let {
    deliver: bool = $context.flow.process_cip_io(this);
} &byteorder=littleendian;

###################################################################################################
##################################  END OF ZEEK CONNECTION DATA  ##################################
###################################################################################################


###################################################################################################
#####################################  ETHERNET/IP COMMANDS  ######################################
###################################################################################################

## ----------------------------------------ENIP-Originator-----------------------------------------
## Message Description:
##      Ethernet/IP Message sent from the originator to the target.
## Protocol Parsing:
##      Continue with parsing of Ethernet/IP message depending on ENIP command
## ------------------------------------------------------------------------------------------------
type ENIP_Originator(command: uint16) = case command of {
    NOP                     -> nop:                     Nop;
    LIST_IDENTITY           -> list_identity:           empty;
    LIST_INTERFACES         -> list_interfaces:         empty;
    REGISTER_SESSION        -> register_session:        Register_Session;
    UNREGISTER_SESSION      -> unregister_session:      empty;
    LIST_SERVICES           -> list_services:           empty;
    SEND_RR_DATA            -> send_rr_data:            Send_RR_Data;
    SEND_UNIT_DATA          -> send_unit_data:          Send_Unit_Data;
    default                 -> unknown:                 bytestring &restofdata;
};

## ------------------------------------------ENIP-Target-------------------------------------------
## Message Description:
##      Ethernet/IP Message sent from the target to the originator.
## Protocol Parsing:
##      Continue with parsing of Ethernet/IP message depending on ENIP command
## ------------------------------------------------------------------------------------------------
type ENIP_Target(command: uint16) = case command of {
    NOP                     -> nop:                     Nop;
    LIST_IDENTITY           -> list_identity:           List_Identity_Response;
    LIST_INTERFACES         -> list_interfaces:         List_Interfaces_Response;
    REGISTER_SESSION        -> register_session:        Register_Session;
    UNREGISTER_SESSION      -> unregister_session:      empty;
    LIST_SERVICES           -> list_services:           List_Services_Response;
    SEND_RR_DATA            -> send_rr_data:            Send_RR_Data;
    SEND_UNIT_DATA          -> send_unit_data:          Send_Unit_Data;
    default                 -> unknown:                 bytestring &restofdata;
};

## ------------------------------------------ENIP-Header-------------------------------------------
## Message Description:
##      Ethernet/IP fixed length 24 byte header.
## Message Format:
##      - Command:                  uint16              -> Ethernet/IP Command (see command_codes)
##      - Length:                   uint16              -> Length of ENIP data following header
##      - Session Handle:           uint32              -> Session identification
##      - Status:                   uint32              -> Status code
##      - Sender Context:           uint8[8]            -> Sender Context 
##      - Options:                  uint32              -> Options Flags
## Protocol Parsing:
##      Sends header information to the enip_header event. By default this is then logged to the 
##      enip.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type ENIP_Header(command: uint16) = record {
    #command                 : uint16;
    length                  : uint16;
    session_handle          : uint32;
    status                  : uint32;
    sender_context          : bytestring &length=8;
    options                 : uint32;
} &let {
    deliver: bool = $context.flow.process_enip_header(this);
} &byteorder=littleendian;

## ----------------------------------------------NOP-----------------------------------------------
## Message Description:
##      A NOP (No Operation) command can be sent by either an originator or a target. No reply
##      shall be generated by the command and the receiver shall ignore any data contained in the
##      message.
## Message Format:
##      - Unused Data:              uint8[]      -> Any value (ignored by target)
## Protocol Parsing:
##      No event created for NOP command as all data should be ignored by target
## ------------------------------------------------------------------------------------------------
type Nop = record {
    unused_data             : bytestring &restofdata;
} &byteorder=littleendian;

## -------------------------------------List-Identity-Response-------------------------------------
## Message Description:
##      An originator may use the ListIdentity command to locate and identify potential targets.
##      The targets shall respond with the appropriate data items.
## Message Format:
##      - Item Count:               uint16              -> Number of target items to follow
##      - Target Items:             CPF_Item[]          -> CIP Identity/Security or ENIP Capability
## Protocol Parsing:
##      Continue with parsing of target items (see CIP_Identity_Item, ENIP_Capability_Item, and
##      CIP_Security_Item)
## ------------------------------------------------------------------------------------------------
type List_Identity_Response = record {
    item_count              : uint16;
    target_items            : Common_Packet_Format_Item[item_count];
} &byteorder=littleendian;

## ------------------------------------List-Interfaces-Response------------------------------------
## Message Description:
##      The optional ListInterfaces command shall be used by an originator to identify non-CIP
##      communication interfaces associated with the target.
## Message Format:
##      - Item Count:               uint16              -> Number of target items to follow
##      - Target Items:             CPF_Item[]          -> See Common Packet Format Item
## Protocol Parsing:
##      Continue with parsing of target items (see Common_Packet_Format_Item)
## ------------------------------------------------------------------------------------------------
type List_Interfaces_Response = record {
    item_count              : uint16;
    target_items            : Common_Packet_Format_Item[item_count];
} &byteorder=littleendian;

## ----------------------------------------Register-Session----------------------------------------
## Message Description:
##      An originator shall send a RegisterSession command to a target to initiate a session
## Message Format:
##      - Protocol Version:         uint16              -> Version of Protocol (currently 1)
##      - Options Flag:             uint16              -> Options Flag (no public options defined)
## Protocol Parsing:
##      Sends protocol version and options flag to the register_session event
## ------------------------------------------------------------------------------------------------
type Register_Session = record {
    protocol_version        : uint16;
    options_flags           : uint16;
} &let {
    deliver: bool = $context.flow.process_register_session(this);
} &byteorder=littleendian;

## -------------------------------------List-Services-Response-------------------------------------
## Message Description:
##      The ListServices command shall determine which encapsulation service classes the target
##      device supports.
## Message Format:
##      - Item Count:               uint16              -> Number of target items to follow
##      - Target Items:             CPF_Item[]          -> See Service_Item
## Protocol Parsing:
##      Continue with parsing of target items (see Service_Item)
## ------------------------------------------------------------------------------------------------
type List_Services_Response = record {
    item_count              : uint16;
    target_items            : Common_Packet_Format_Item[item_count];
} &byteorder=littleendian;

## ------------------------------------------Send-RR-Data------------------------------------------
## Message Description:
##      A SendRRData command shall transfer an encapsulated request/reply packet between the
##      originator and target, where the originator initiates the command
## Message Format:
##      - Interface Handle:         uint32              -> Should be 0 for CIP packets
##      - Timeout:                  uint16              -> Timout for when request expires
##      - Item Count:               uint16              -> Number of target items to follow
##      - Target Items:             CPF_Item[]          -> See Common Packet Format Item
## Protocol Parsing:
##      Continue with parsing of target items (see Common_Packet_Format_Item)
## ------------------------------------------------------------------------------------------------
type Send_RR_Data = record {
    interface_handle        : uint32;
    timeout                 : uint16;
    item_count              : uint16;
    encap_items             : Common_Packet_Format_Item[item_count];
} &byteorder=littleendian;

## -----------------------------------------Send-Unit-Data-----------------------------------------
## Message Description:
##      The SendUnitData command shall send encapsulated connected messages. A reply shall not be
##      returned.
## Message Format:
##      - Interface Handle:         uint32              -> Should be 0 for CIP packets
##      - Timeout:                  uint16              -> Should be set to 0 (no reply)
##      - Item Count:               uint16              -> Number of target items to follow
##      - Target Items:             CPF_Item[]          -> See Common Packet Format Item
## Protocol Parsing:
##      Continue with parsing of target items (see Common_Packet_Format_Item)
## ------------------------------------------------------------------------------------------------
type Send_Unit_Data = record {
    interface_handle        : uint32;
    timeout                 : uint16;
    item_count              : uint16;
    encap_items             : Common_Packet_Format_Item[item_count];
} &byteorder=littleendian;

###################################################################################################
##################################  END OF ETHERNET/IP COMMANDS  ##################################
###################################################################################################


###################################################################################################
############################  ETHERNET/IP COMMAND PACKET FORMAT ITEMS  ############################
###################################################################################################

## -----------------------------------Common-Packet-Format-Item------------------------------------
## Message Description:
##      The common packet format (CPF) defines a standard format for protocol packets that are
##      transported with the encapsulation protocol.
## Message Format:
##      - Type ID:                  uint16              -> Type of item (see cpf_item_types)
##      - Length:                   uint16              -> Length in bytes of the data field
##      - Data:                     variable            -> Data (if length > 0)
## Protocol Parsing:
##      Continue with parsing of target items according to Type ID.
## ------------------------------------------------------------------------------------------------
type Common_Packet_Format_Item = record {
    item_type               : uint16;
    item_length             : uint16;
    item_data               : case item_type of {
        NULL_ADDRESS                    -> null_address:                    empty;
        CIP_IDENTITY                    -> cip_identity_item:               CIP_Identity_Item;
        CIP_SECURITY                    -> cip_security_item:               CIP_Security_Item;
        ENIP_CAPABILITY                 -> enip_capability:                 ENIP_Capability_Item;
        CONNECTED_ADDRESS               -> connected_address:               Connected_Address_Item;
        CONNECTED_TRANSPORT_DATA        -> connected_transport_data:        Connected_Data_Item(item_length);
        UNCONNECTED_MESSAGE_DATA        -> unconnected_message_data:        Unconnected_Data_Item(item_length);
        LIST_SERVICES_RESPONSE          -> list_services_response:          Service_Item;
        SOCK_ADDR_DATA_ORIG_TO_TARGET   -> sock_addr_data_orig_to_target:   Socket_Address_Info_Item;
        SOCK_ADDR_DATA_TARGET_TO_ORIG   -> sock_addr_data_target_to_orig:   Socket_Address_Info_Item;
        SEQUENCED_ADDRESS_ITEM          -> sequenced_address_item:          Sequenced_Address_Item;
        UNCONNECTED_MESSAGE_DTLS        -> unconnected_message_dtls:        Unconnected_Message_DTLS(item_length);
        default                         -> unknown:                         bytestring &restofdata;
    };
} &byteorder=littleendian;

## ---------------------------------------CIP-Identity-Item----------------------------------------
## Message Description:
##      The CIP Identity Item shall be the first item returned in a ListIdentity Response. This 
##      item describes data and functionality of CIP object/device.
## Message Format:
##      - Encapsulation Version:    uint16              -> Encapsulation Protocol Version supported
##      - Socket Address Info:      struct              -> See Socket_Address_Info_Item
##      - Vendor ID:                uint16              -> Device manufacturer's Vendor ID
##      - Device Type:              uint16              -> Device type of product
##      - Product Code:             uint16              -> Product code assigned to device
##      - Revision (Major):         uint8               -> Device revision (major)
##      - Revision (Minor):         uint8               -> Device revision (minor)
##      - Status:                   uint16              -> Current status of device
##      - Serial Number:            uint32              -> Serial number of device
##      - Product Name Length:      uint8               -> Length (in bytes) of Product Name
##      - Product Name:             string              -> Human readable description of device
##      - State:                    uint16              -> Current state of device
## Protocol Parsing:
##      Sends all variables to the cip_identity event. By default this is then logged to the 
##      cip_identity.log file as defined in main.zeek.
## ------------------------------------------------------------------------------------------------
type CIP_Identity_Item = record {
    encapsulation_version   : uint16;
    socket_address          : Socket_Address_Info_Item;
    vendor_id               : uint16;
    device_type             : uint16;
    product_code            : uint16;
    revision_major          : uint8;
    revision_minor          : uint8;
    status                  : uint16;
    serial_number           : uint32;
    product_name_length     : uint8;
    product_name            : bytestring &length=(product_name_length);
    state                   : uint8;
} &let {
    deliver: bool = $context.flow.process_cip_identity_item(this);
} &byteorder=littleendian;

## ---------------------------------------CIP-Security-Item----------------------------------------
## Message Description:
##      The CIP Security Item shall be included in a ListIdentity Response for all CIP Security 
##      capable devices. It describes the security state and functionality of the device.
## Message Format:
##      - Security Profiles:        uint16              -> CIP Security Profiles supported
##      - CIP Security State:       uint8               -> Current state of CIP Security Object
##      - ENIP Security State:      uint8               -> Current state of ENIP Security Object
##      - IANA Port State:          int8                -> Current state for ENIP related ports
##          + 1 (True) indicates port is open, 0 (False) indicates port is closed
##          + Bit 0:    44818/tcp
##          + Bit 1:    44818/udp
##          + Bit 2:    2222/ucp
##          + Bit 3:    2221/tcp
##          + Bit 4:    2221/udp
##          + Bit 5-7:  Reserved
## Protocol Parsing:
##      Sends all variables to the cip_security event.
## ------------------------------------------------------------------------------------------------
type CIP_Security_Item = record {
    security_profile        : uint16;
    cip_security_state      : uint8;
    enip_security_state     : uint8;
    iana_port_state         : int8;
} &let {
    deliver: bool = $context.flow.process_cip_security_item(this);
} &byteorder=littleendian;

## --------------------------------------ENIP-Capability-Item--------------------------------------
## Message Description:
##      The Ethernet/IP Capability Item can be included in a ListIdentity Response and is used to
##      define Ethernet/IP transport capabilities for the various message types for a device.
## Message Format:
##      - ENIP Profile:             uint32              -> Features supported for ENIP transport
## Protocol Parsing:
##      Sends enip_profile to the enip_capability event.
## ------------------------------------------------------------------------------------------------
type ENIP_Capability_Item = record {
    enip_profile            : uint32;
} &let {
    deliver: bool = $context.flow.process_enip_capability_item(this);
} &byteorder=littleendian;

## ------------------------------------Socket-Address-Info-Item------------------------------------
## Message Description:
##      The Sockaddr Info items shall be used to communicate IP address or port information
##      necessary to create Class 0 or Class 1 connections
## Message Format:
##      - sin_family:               int16               -> Shall be AF_INET = 2
##      - sin_port:                 uint16              -> Socket Address Port Number
##      - sin_addr:                 uint32              -> Socket Address IP address
##      - sin_zero:                 uint8[8]            -> Length of 8, should be set to all 0
## Protocol Parsing:
##      Sends sin_addr and sin_port to the socket_address_info event
## ------------------------------------------------------------------------------------------------
type Socket_Address_Info_Item = record {
    sin_family              : int16;
    sin_port                : uint16;
    sin_addr                : uint32;
    sin_zero                : uint8[8];
} &let {
    deliver: bool = $context.flow.process_socket_address_info(this);
} &byteorder=littleendian;

## ------------------------------------------Service-Item------------------------------------------
## Message Description:
##      Shows service classes the target device supports
## Message Format:
##      - Protocol Version:         uint16              -> Version of Protocol (currently 1)
##      - Capability Flags:         uint16              -> Capability Flags
##      - Name of Service:          uint8[16]           -> Name of Service
## Protocol Parsing:
##      Sends protocol_version, capability_flags, and service_name to enip_service event
## ------------------------------------------------------------------------------------------------
type Service_Item = record {
    protocol_version        : uint16;
    capability_flags        : uint16;
    service_name            : bytestring &length=16;
} &let {
    deliver: bool = $context.flow.process_service_item(this);
} &byteorder=littleendian;

## -------------------------------------Connected-Address-Item-------------------------------------
## Message Description:
##      This address item shall be used when the encapsulated protocol is connection-oriented. The
##      data shall contain a connection identifier.
## Message Format:
##      - Connection Identifier:    uint32              -> Connection Identifier
## Protocol Parsing:
##      Sends connection_identifier to the connected_address event
## ------------------------------------------------------------------------------------------------
type Connected_Address_Item = record {
    connection_identifier   : uint32;
} &let {
    deliver: bool = $context.flow.process_connected_address_item(this);
} &byteorder=littleendian;

## -------------------------------------Sequenced-Address-Item-------------------------------------
## Message Description:
##      This address item shall be used for CIP transport class 0 and class 1 connected data. The data
##      shall contain a connection identifier and an Encapsulation Sequence Number.
## Message Format:
##      - Connection Identifier:    uint32              -> Connection Identifier
##      - Encap Sequence Number:    uint32              -> Encapsulation Sequence Number
## Protocol Parsing:
##      Sends connection_identifier and encap_sequence_number to the sequenced_address event
## ------------------------------------------------------------------------------------------------
type Sequenced_Address_Item = record {
    connection_identifier   : uint32;
    encap_sequence_number   : uint32;
} &let {
    deliver: bool = $context.flow.process_sequenced_address_item(this);
} &byteorder=littleendian;

## -------------------------------------Unconnected-Data-Item--------------------------------------
## Message Description:
##      A data item that encapsulates an unconnected message
## Message Format:
##      - Data:                     CIP_Header          -> Unconnected Message (see CIP_Header)
## Protocol Parsing:
##      Continue with parsing of CIP Data (see CIP_Header)
## ------------------------------------------------------------------------------------------------
type Unconnected_Data_Item(message_size: uint16) = record {
    unconnected_message     : CIP_Header(0);
} &byteorder=littleendian;

## --------------------------------------Connected-Data-Item---------------------------------------
## Message Description:
##      A data item that encapsulates a connected transport packet
## Message Format:
##      - CIP Sequence Count:       uint16              -> CIP sequence number for transport
##      - Data:                     CIP_Header          -> Transport Packet (see CIP_Header)
## Protocol Parsing:
##      Continue with parsing of CIP Data (see CIP_Header)
## ------------------------------------------------------------------------------------------------
type Connected_Data_Item(message_size: uint16) = record {
    cip_sequence_count      : uint16;
    transport_packet        : CIP_Header(cip_sequence_count);
} &byteorder=littleendian;

## ------------------------------------Unconnected-Message-DTLS------------------------------------
## Message Description:
##      A data item that enapsulates an unconnected message via a DTLS session.
## Message Format:
##      - Unconnected Message Type: uint16              -> Type of unconnected message
##      - Transaction Number:       uint32              -> Used for request/reply matching
##      - Status:                   uint16              -> Status (see enip_status_codes)
##      - Unconnected Message:      CIP_Header          -> Unconnected Message (see CIP_Header)
## Protocol Parsing:
##      Sends unconn_message_type, transaction_number, and status to the unconnected_message_dtls
##      event and then continues with parsing of CIP Data (see CIP_Header).
## ------------------------------------------------------------------------------------------------
type Unconnected_Message_DTLS(message_size: uint16) = record {
    unconn_message_type     : uint16;
    transaction_number      : uint32;
    status                  : uint16;
    unconnected_message     : CIP_Header(0);
} &let {
    deliver: bool = $context.flow.process_unconnected_message_dtls(this);
} &byteorder=littleendian;

###################################################################################################
########################  END OF ETHERNET/IP COMMAND PACKET FORMAT ITEMS  #########################
###################################################################################################


###################################################################################################
#########################################  CIP COMMANDS  ##########################################
###################################################################################################

## -------------------------------------------CIP-Header-------------------------------------------
## Message Description:
##      CIP header for encapsulated CIP services within Ethernet/IP packets
## Message Format:
##      - Service:                  uint8               -> CIP Service (see cip_common_services)
##      - Request Path:             Request_Path        -> See Request_Path
##      - Status Code:              empty/CIP_Status    -> See CIP_Status if response packet
##      - Data:                     variable            -> CIP service specific data
## Protocol Parsing:
##      Sends CIP header information to the cip_header event and continues on with CIP service 
##      parsing. By default, CIP header info is logged to the cip.log file as defined in main.zeek. 
## ------------------------------------------------------------------------------------------------
type CIP_Header(cip_sequence_count: uint16) = record {
    service                 : uint8;
    request_path            : Request_Path;
    status_code             : case (service >> 7) of {
        1               -> response_packet: CIP_Status;
        default         -> request_packet: empty;
    };
    data                    : case service of {
        GET_ATTRIBUTES_ALL              -> get_attributes_all_request:      empty;
        GET_ATTRIBUTES_ALL_RESPONSE     -> get_attributes_all_response:     Get_Attributes_All_Response;
        GET_ATTRIBUTE_LIST              -> get_attribute_list:              Get_Attribute_List_Request;
        GET_ATTRIBUTE_LIST_RESPONSE     -> get_attribute_list_response:     Get_Attribute_List_Response;
        SET_ATTRIBUTE_LIST              -> set_attribute_list:              Set_Attribute_List_Request;
        SET_ATTRIBUTE_LIST_RESPONSE     -> set_attribute_list_response:     Set_Attribute_List_Response;
        MULTIPLE_SERVICE                -> multiple_service_request:        Multiple_Service_Packet_Request;
        MULTIPLE_SERVICE_RESPONSE       -> multiple_service_response:       Multiple_Service_Packet_Response;
        GET_ATTRIBUTE_SINGLE_RESPONSE   -> get_attribute_single_response:   Get_Attribute_Single_Response;
        SET_ATTRIBUTE_SINGLE            -> set_attribute_single_request:    Set_Attribute_Single_Request;
        default                         -> other:                           bytestring &restofdata;
    };
} &let {
    status                  : uint8   = case(service >> 7) of {
        1               -> response_packet.status;
        default         -> 5;
    };
    request_or_response     : uint8 = (service >> 7);
    service_code            : uint8 = (service & 0x7f);
    deliver: bool = $context.flow.process_cip_header(this);
} &byteorder=littleendian;

## -------------------------------------------CIP-Status-------------------------------------------
## Message Description:
##      Status Code sent in CIP response packets.
## Message Format:
##      - Status:                   uint8               -> CIP status code
##      - Status Extra:             uint8               -> Size of extended status
##      - Extended Status:          uint8[]             -> CIP extended status code
## Protocol Parsing:
##      Continues with parsing of CIP data
## ------------------------------------------------------------------------------------------------
type CIP_Status = record {
    status                  : uint8;
    status_extra            : uint8;
    status_extended         : uint8[status_extra];
} &byteorder=littleendian;

## ------------------------------------------Request-Path------------------------------------------
## Message Description:
##      CIP Request path transport information. Additional parsing of the request path is done in
##      enip_analyzer.pac function parse_request_path.
## Message Format:
##      - Request Path Size:        uint8               -> Size of request path
##      - Request Path:             uint16[]            -> Request Path Data
## Protocol Parsing:
##      Continues with parsing of CIP data
## ------------------------------------------------------------------------------------------------
type Request_Path = record {
    request_path_size       : uint8;
    request_path            : bytestring &length=request_path_size*2;
} &byteorder=littleendian;

## ----------------------------------Get-Attributes-All-Response-----------------------------------
## Message Description:
##      Returns the contents of the instance or class attributes defined in the object definition.
##      CIP Service Code 0x01 - Response Only (No Request Data)
## Message Format:
##      - Attribute Data:           variable            -> Attribute data based on instance/class
## Protocol Parsing:
##      Sends attribute_data to the get_attribute_all_response event. Cannot do further processing
##      on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Get_Attributes_All_Response = record {
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_get_attribute_all_response(this);
} &byteorder=littleendian;

## -----------------------------------Set-Attributes-All-Request-----------------------------------
## Message Description:
##      Modifies the contents of the instance or class attributes defined in the object definition.
##      CIP Service Code 0x02 - Request Only (No Response Data)
## Message Format:
##      - Attribute Data:           variable            -> Attribute data based on object/class
## Protocol Parsing:
##      Sends attribute_data to the set_attribute_all_request event. Cannot do further processing
##      on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Set_Attributes_All_Request = record {
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_set_attribute_all_request(this);
} &byteorder=littleendian;

## -----------------------------------Get-Attribute-List-Request-----------------------------------
## Message Description:
##      The Get_Attribute_List service shall return the contents of the selected gettable 
##      attributes of the specified object class or instance
##      CIP Service Code 0x03 - Request
## Message Format:
##      - Attribute Count:          uint16              -> Number of attribute IDs in list
##      - Attribute List:           uint16[]            -> List of attribute IDs
## Protocol Parsing:
##      Sends attribute_count and attribute_list to the get_attribute_list_request event.
## ------------------------------------------------------------------------------------------------
type Get_Attribute_List_Request = record {
    attribute_count         : uint16;
    attribute_list          : uint16[attribute_count];
} &let {
    deliver: bool = $context.flow.process_get_attribute_list_request(this);
} &byteorder=littleendian;

## ----------------------------------Get-Attribute-List-Response-----------------------------------
## Message Description:
##      The Get_Attribute_List service shall return the contents of the selected gettable 
##      attributes of the specified object class or instance
##      CIP Service Code 0x03 - Response
## Message Format:
##      - Attribute Count:          uint16              -> Number of attribute structs
##      - Attribute Data:           variable[]          -> Struct of attribute responses
## Protocol Parsing:
##      Sends attribute_count and attribute_data to the get_attribute_list_response event. Cannot 
##      do further processing on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Get_Attribute_List_Response = record {
    attribute_count         : uint16;
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_get_attribute_list_response(this);
} &byteorder=littleendian;

## -----------------------------------Set-Attribute-List-Request-----------------------------------
## Message Description:
##      The Set_Attribute_List service shall set the contents of selected attributes of the 
##      specified object class or instance.
##      CIP Service Code 0x04 - Request
## Message Format:
##      - Attribute Count:          uint16              -> Number of attribute structs
##      - Attribute Data:           variable[]          -> Struct of attribute responses
## Protocol Parsing:
##      Sends attribute_count and attribute_data to the set_attribute_list_request event. Cannot 
##      do further processing on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Set_Attribute_List_Request = record {
    attribute_count         : uint16;
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_set_attribute_list_request(this);
} &byteorder=littleendian;

## ----------------------------------Set-Attribute-List-Response-----------------------------------
## Message Description:
##      The Set_Attribute_List service shall set the contents of selected attributes of the 
##      specified object class or instance.
##      CIP Service Code 0x04 - Response
## Message Format:
##      - Attribute Count:          uint16              -> Number of attribute structs
##      - Attribute Data:           variable[]          -> Struct of attribute responses
## Protocol Parsing:
##      Sends attribute_count and attribute_data to the set_attribute_list_response event. Cannot 
##      do further processing on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Set_Attribute_List_Response = record {
    attribute_count         : uint16;
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_set_attribute_list_response(this);
} &byteorder=littleendian;

## --------------------------------Multiple-Service-Packet-Request---------------------------------
## Message Description:
##      Performs a set of services as an autonomous sequence.
##      CIP Service Code 0x0A - Request
## Message Format:
##      - Service Count:            uint16              -> Number of services
##      - Service Offsets:          uint16[]            -> List of service offsets
##      - Services:                 variable            -> Services
## Protocol Parsing:
##      Sends message data to the multiple_service_request event.
## ------------------------------------------------------------------------------------------------
type Multiple_Service_Packet_Request = record {
    service_count           : uint16;
    service_offsets         : uint16[service_count];
    services                : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_multiple_service_request(this);
} &byteorder=littleendian;

## --------------------------------Multiple-Service-Packet-Response--------------------------------
## Message Description:
##      Performs a set of services as an autonomous sequence.
##      CIP Service Code 0x0A - Response
## Message Format:
##      - Service Count:            uint16              -> Number of services
##      - Service Offsets:          uint16[]            -> List of service offsets
##      - Services:                 variable            -> Services
## Protocol Parsing:
##      Sends message data to the multiple_service_response event.
## ------------------------------------------------------------------------------------------------
type Multiple_Service_Packet_Response = record {
    service_count           : uint16;
    service_offsets         : uint16[service_count];
    services                : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_multiple_service_response(this);
} &byteorder=littleendian;

## ---------------------------------Get-Attribute-Single-Response----------------------------------
## Message Description:
##      Returns the contents of the specified attribute or other logical elements
##      CIP Service Code 0x0E - Response only (No Request Data)
## Message Format:
##      - Attribute Data:           variable            -> Struct of attribute response
## Protocol Parsing:
##      Sends attribute_data to the get_attribute_single_response event. Cannot do further 
##      processing on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Get_Attribute_Single_Response = record {
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_get_attribute_single_response(this);
} &byteorder=littleendian;

## ----------------------------------Set-Attribute-Single-Request----------------------------------
## Message Description:
##      Modifies an attribute value.
##      CIP Service Code 0x10 - Request only (No Response Data)
## Message Format:
##      - Attribute ID:             uint8               -> Identifies the attribute
##      - Attribute Data:           variable            -> Value of modified attribute
## Protocol Parsing:
##      Sends attribute_id and attribute_data to the set_attribute_single_response event. Cannot 
##      do further processing on attribute data because it is instance/class specific
## ------------------------------------------------------------------------------------------------
type Set_Attribute_Single_Request = record {
    attribute_id            : uint8;
    attribute_data          : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_set_attribute_single_request(this);
} &byteorder=littleendian;

###################################################################################################
######################################  END OF CIP COMMANDS  ######################################
###################################################################################################
