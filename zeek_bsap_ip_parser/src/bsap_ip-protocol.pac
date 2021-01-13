## bsap_ip-protocol.pac
##
## Binpac BSAP_IP Protocol Analyzer - Defines BSAP_IP Protocol Message Formats
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

## BSAP_IP Record Types
%include consts.pac

## --------------------------------------------BSAP-PDU--------------------------------------------
## Message Description:
##      Main BSAP PDU
## Message Format:
##      - header:                   BSAPIP_Header       -> See BSAPIP_Header
##      - body:                     GET_BSAP            -> GET_BSAP
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP_Response or BSAP_Request parsing function.
## ------------------------------------------------------------------------------------------------
type BSAP_IP_PDU(is_orig: bool) = record {
    header                  : BSAPIP_Header;
    body                    : GET_BSAP(header);
}&let {
    deliver: bool = $context.flow.proc_bsap_ip_message(this);
} &byteorder=littleendian;

## -------------------------------------------BSAPIP_Header----------------------------------------
## Message Description:
##      BSAPIP_Header
## Message Format:
##      - id:                      uint16              -> Message format ID
##      - Num_Messages:            uint16              -> This is either amount of functions per
##                                                        message or is standard vs poll message.
##
##      - Message_Func:            uint16              -> Determines message type
##
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP Local or BSAP Global message parsing depending on the ADDR value.
## ------------------------------------------------------------------------------------------------
type BSAPIP_Header = record {
    id                      : uint16;
    Num_Messages            : uint16;
    Message_Func            : uint16;
} &byteorder=littleendian;

## ------------------------------------------GET_BSAP----------------------------------------------
## Message Description:
##      GET_BSAP determines the correct function to process the bsap message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Message_Func value
## ------------------------------------------------------------------------------------------------
type GET_BSAP(header: BSAPIP_Header) = case header.Message_Func of {
    CMD_REQUEST                         -> request:                 BSAP_Request;
    CMD_RESPONSE                        -> response:                BSAP_Response;
    CMD_RESPONSE_1                      -> response_1:              BSAP_Response;
    default                             -> unknown:                 BSAPIP_Unknown;
} 

## -----------------------------------------BSAP_Request-------------------------------------------
## Message Description:
##      BSAP_Request
## Message Format:
##      - header:                  BSAP_Request_Header -> See BSAP_Request_Header
##      - body:                    BSAP_Get_Request    -> See BSAP_Get_Request
##
## Protocol Parsing:
##      Parses BSAP request header data and passes the information to the 
##      correct function to finish parsing. 
## ------------------------------------------------------------------------------------------------
type BSAP_Request = record {
    header                  : BSAP_Request_Header;
    body                    : BSAP_Get_Request(header);
} &byteorder=littleendian;

## ----------------------------------BSAP_Request_Header-------------------------------------------
## Message Description:
##      BSAP_Request_Header
## Message Format:
##      - response_seq:             uint32              -> Message Response Sequence
##      - message_seq:              uint32              -> Message Sequence
##      - data_length:              uint32              -> Message Length
##      - header_size:              uint8               -> Header Length
##      - sequence:                 uint32              -> Function sequence 
##      - app_func_code:            uint8               -> Application function code        
##                                                                                                              
## Protocol Parsing:
##      BSAP request header information    
## ------------------------------------------------------------------------------------------------
type BSAP_Request_Header = record {
    response_seq            : uint32;
    message_seq             : uint32;
    data_length             : uint32;
    header_size             : uint8;
    sequence                : uint32;
    app_func_code           : uint8;
}&let {
    deliver: bool = $context.flow.proc_bsap_request_header(this);
} &byteorder=littleendian;

## ------------------------------------------BSAP_Get_Request--------------------------------------
## Message Description:
##      BSAP_Get_Request determines the correct function to process the message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on app_func_code command.
##      If function isn't implemented we pass to Unknown to be logged.
## ------------------------------------------------------------------------------------------------
type BSAP_Get_Request(header: BSAP_Request_Header) = case header.app_func_code of {
    RDB                                 -> remotedatabase:          RDB_Request;
    default                             -> dflt:                    BSAPIP_Unknown;
}

## --------------------------------------------RDB_Request-----------------------------------------
## Message Description:
##      RDB_Request is remote data base access for reading and writing RTU variables 
## Message Format:
##      node_status:                uint8                   -> Node status byte
##      func_code:                  uint8                   -> Function that will be called
##      data:                       bytestring &restofdata  -> data passed for function call
## Protocol Parsing:
##      Parses function code from message and stores rest of message in data to be 
##      stored in bsap_cnv_rdb.log file. 
## ------------------------------------------------------------------------------------------------
type RDB_Request = record {
    node_status             : uint8;
    func_code               : uint8;
    data                    : bytestring &restofdata;        
} &let {
    deliver: bool = $context.flow.proc_bsap_rdb_request(this);
} &byteorder=littleendian;

## --------------------------------------------BSAP_Response-----------------------------------------
## Message Description:
##      RDB_Response is remote data base access response to the initiated request.
## Message Format:
##      message_seq:                uint32                  -> Message Sequence
##      response_seq:               uint32                  -> Message Response Sequence
##      data_length:                uint32                  -> Message Length
##      header_size:                uint8                   -> Header Length
##      sequence:                   uint32                  -> Function sequence 
##      resp_status:                uint8                   -> Response Status
##      nme:                        uint8                   -> Number of message elements
##      data:                       bytestring &restofdata  -> data passed for response
## Protocol Parsing:
##      Parses function code from message and stores rest of message in data to be 
##      stored in bsap_cnv_rdb.log file. 
## ------------------------------------------------------------------------------------------------
type BSAP_Response = record {
    message_seq             : uint32;
    response_seq            : uint32;
    data_length             : uint32;
    header_size             : uint8;
    sequence                : uint32;
    resp_status             : uint8;
    nme                     : uint8;
    data                    : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.proc_bsap_response(this);
} &byteorder=littleendian;

type BSAPIP_Unknown = record {
    data                    : bytestring &restofdata;
} &byteorder=littleendian;


