## bsap_serial-protocol.pac
##
## Binpac BSAP_SERIAL Analyzer - Defines BSAP Protocol for parsing
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
## 
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

## BSAP Record Types
%include consts.pac

## --------------------------------------------BSAP-PDU--------------------------------------------
## Message Description:
##      Main BSAP PDU
## Message Format:
##      - header:                   BSAP_Header         -> See BSAP_Header
##      - body:                     GET_BSAP_GLBL_LOCAL -> GET_BSAP_GLBL_LOCAL
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP Local or BSAP Global message parsing depending on the ADDR value.
## ------------------------------------------------------------------------------------------------
type BSAP_SERIAL_PDU(is_orig: bool) = record {
    header                  : BSAP_Header;
    body                    : GET_BSAP_GLBL_LOCAL(header);
}&let {
    deliver: bool = $context.flow.proc_bsap_serial_message(this);
} &byteorder=littleendian; 

## --------------------------------------------BSAP-Header-----------------------------------------
## Message Description:
##      Main Ethernet/IP PDU
## Message Format:
##      - DLE:                      uint8               -> Always 0x10
##      - STX:                      uint8               -> Start transmit always 0x02
##      - ADDR:                     uint8               -> Address of device 0x00-0x7F local addr
##                                                         localaddr+0x80  global msg
## Protocol Parsing:
##      Starts protocol parsing by getting BSAP header and passes processing to either
##      BSAP Local or BSAP Global message parsing depending on the ADDR value.
## ------------------------------------------------------------------------------------------------
type BSAP_Header = record {
    DLE                     : uint8;
    STX                     : uint8;
    ADDR                    : uint8;
} &byteorder=littleendian;

## ---------------------------------------GET-BSAP-GLBL-LOCAL--------------------------------------
## Message Description:
##      BSAP GLBL LOCAL determines the BSAP header type if either local or global. 
## Message Format:
##      - LOCAL:                    local               -> see BSAP_Local
##      - GLOBAL:                   global              -> see BSAP_Global
##      - default:                  dflt                -> see BSAP_Local
## Protocol Parsing:
##      Passes processing to either BSAP_Local or BSAP_Global based off of header.ADDR
## ------------------------------------------------------------------------------------------------
type GET_BSAP_GLBL_LOCAL(header: BSAP_Header) = case (header.ADDR >> 7) of {
    LOCAL                               -> local:                   BSAP_Local;
    GLOBAL                              -> global:                  BSAP_Global;
    default                             -> dflt:                    BSAP_Local;
} 

## ----------------------------------------GET_BSAP_GLOBAL-----------------------------------------
## Message Description:
##      GET_BSAP_GLOBAL determines the correct function to process the global message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Destination Function (DFUN) command
## ------------------------------------------------------------------------------------------------
type GET_BSAP_GLOBAL(header: BSAP_Global_Header) = case header.DFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Unknown;
    PEI_PC                              -> pei_pc:                  On_Line_PEI_PC_GLOBAL(header);
    DIAG                                -> diag:                    BSAP_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Unknown;
    RDB                                 -> remotedatabase:          RDB_Request;
    RDB_EXTENSION                       -> remotedatabaseext:       RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Unknown;
    default                             -> poll:                    BSAP_Unknown;
} 

## ----------------------------------------GET_BSAP_LOCAL------------------------------------------
## Message Description:
##      GET_BSAP_LOCAL determines the correct function to process the local message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Destination Function (DFUN) command
## ------------------------------------------------------------------------------------------------
type GET_BSAP_LOCAL(header: BSAP_Local_Header) = case header.DFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Unknown;
    PEI_PC                              -> pei_pc:                  On_Line_PEI_PC_LOCAL(header);
    DIAG                                -> diag:                    BSAP_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Unknown;
    RDB                                 -> remotedatabase:          RDB_Request;
    RDB_EXTENSION                       -> remotedatabaseext:       RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Unknown;
    default                             -> poll:                    BSAP_Unknown;
} 

## ----------------------------------------On_Line_PEI_PC_GLOBAL-----------------------------------
## Message Description:
##      On_Line_PEI_PC_GLOBAL determines the correct function to process the global message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Source Function (SFUN) command
## ------------------------------------------------------------------------------------------------
type On_Line_PEI_PC_GLOBAL(header: BSAP_Global_Header) = case header.SFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Unknown;
    PEI_PC                              -> pei_pc:                  BSAP_Unknown;
    DIAG                                -> diag:                    BSAP_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Unknown;
    RDB                                 -> remotedatabase:          RDB_Response;
    RDB_EXTENSION                       -> remotedatabaseext:       RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Unknown;
    default                             -> poll:                    BSAP_Unknown;
}

## ----------------------------------------On_Line_PEI_PC_LOCAL------------------------------------
## Message Description:
##      GET_BSAP_GLOBAL determines the correct function to process the local message.
## Protocol Parsing:
##      Continue with parsing of BSAP message depending on Source Function (SFUN) command
## ------------------------------------------------------------------------------------------------
type On_Line_PEI_PC_LOCAL(header: BSAP_Local_Header) = case header.SFUN of {
    ILLEGAL                             -> illegal:                 BSAP_Unknown;
    PEI_PC                              -> pei_pc:                  BSAP_Unknown;
    DIAG                                -> diag:                    BSAP_Unknown;
    FLASH_DOWNLOAD                      -> flash:                   BSAP_Unknown;
    FLASH_CONFIG                        -> flashconfig:             BSAP_Unknown;
    RDB                                 -> remotedatabase:          RDB_Response;
    RDB_EXTENSION                       -> remotedatabaseext:       RDB_Extension;
    RBE_FIRM                            -> reportbyexcpt_firm:      BSAP_Unknown;
    RBE_MNGR                            -> reportbyexcpt_mang:      BSAP_Unknown;
    default                             -> poll:                    BSAP_Unknown;
}

## --------------------------------------------BSAP_Local-------------------------------------------
## Message Description:
##      BSAP_Local grabs local header and passes to GET_BSAP_LOCAL function to parse message
## Message Format:
##      - header:                   BSAP_Local_Header         -> See BSAP_Local_Header
##      - body:                     GET_BSAP_LOCAL            -> GET_BSAP_LOCAL
## Protocol Parsing:
##      Gets header for BSAP Local message and passes header data to function
##      GET_BSAP_LOCAL to determine the function to process the remaining data.
## ------------------------------------------------------------------------------------------------
type BSAP_Local = record {
    header                     : BSAP_Local_Header;
    body                       : GET_BSAP_LOCAL(header);
} &byteorder=littleendian;

## --------------------------------------------BSAP_Global------------------------------------------
## Message Description:
##      BSAP_Global grabs local header and passes to GET_BSAP_GLOBAL function to parse message
## Message Format:
##      - header:                   BSAP_Global_Header         -> See BSAP_Global_Header
##      - body:                     GET_BSAP_GLOBAL            -> GET_BSAP_GLOBAL
## Protocol Parsing:
##      Gets header for BSAP Global message and passes header data to function
##      GET_BSAP_GLOBAL to determine the function to process the remaining data.
## ------------------------------------------------------------------------------------------------
type BSAP_Global = record {
    header                     : BSAP_Global_Header;
    body                       : GET_BSAP_GLOBAL(header);
} &byteorder=littleendian;

## ------------------------------------BSAP_Local_Header-------------------------------------------
## Message Description:
##      BSAP Local header data 
## Message Format:
##      - SER:                      uint8               -> Message Serial Number
##      - DFUN:                     uint8               -> Destination Function
##      - SEQ:                      uint16              -> Message Sequence 
##      - SFUN:                     uint8               -> Source Function
##      - NSB:                      uint8               -> Node Status Byte        
##                                                                                                              
## Protocol Parsing:
##      Bsap Local header data to send to case statement for further processing     
## ------------------------------------------------------------------------------------------------
type BSAP_Local_Header = record {
    SER                     : uint8;
    DFUN                    : uint8;
    SEQ                     : uint16;
    SFUN                    : uint8;
    NSB                     : uint8;
} &let {
    deliver: bool = $context.flow.proc_bsap_local_header(this);
} &byteorder=littleendian;

## ------------------------------------BSAP_Global_Header------------------------------------------
## Message Description:
##      BSAP Global header data 
## Message Format:
##      - SER:                      uint8               -> Message Serial Number
##      - DADD:                     uint16              -> Destination Address
##      - SADD:                     uint16              -> Source Address
##      - CTL:                      uint8               -> Control Byte
##      - DFUN:                     uint8               -> Destination Function
##      - SEQ:                      uint16              -> Message Sequence
##      - SFUN:                     uint8               -> Source Function
##      - NSB:                      uint8               -> Node Status Byte
## Protocol Parsing:
##      Bsap Global header data to send to case statement for further processing
## ------------------------------------------------------------------------------------------------
type BSAP_Global_Header = record {
    SER                     : uint8;
    DADD                    : uint16;
    SADD                    : uint16;
    CTL                     : uint8;
    DFUN                    : uint8;
    SEQ                     : uint16;
    SFUN                    : uint8;
    NSB                     : uint8;
}  &let {
    deliver: bool = $context.flow.proc_bsap_global_header(this);
} &byteorder=littleendian;

## --------------------------------------------RDB_Request-----------------------------------------
## Message Description:
##      RDB_Request is remote data base access for reading and writing RTU variables 
## Message Format:
##      func_code:                  uint8                   -> Function that will be called
##      data:                       bytestring &restofdata  -> data passed for function call
## Protocol Parsing:
##      Parses function code from message and stores rest of message in data to be 
##      stored in bsap_cnv_rdb.log file. 
## ------------------------------------------------------------------------------------------------
type RDB_Request = record {
    func_code               : uint8;
    data                    : bytestring &restofdata;        
} &let {
    deliver: bool = $context.flow.proc_bsap_rdb_request(this);
} &byteorder=littleendian;

## -------------------------------------------RDB_Response-----------------------------------------
## Message Description:
##      RDB_Response is remote data base access response to the initiated request.
## Message Format:
##      data:                       bytestring &restofdata  -> data returned to requester
## Protocol Parsing:
##      Parses data from response message and stores in bsap_cnv_rdb.log file
## ------------------------------------------------------------------------------------------------
type RDB_Response = record {
    data                    : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.proc_bsap_response(this);
} &byteorder=littleendian;

## ------------------------------------------RDB_Extension-----------------------------------------
## Message Description:
##      RDB_Extension is remote data base access request to (GFC 3308) devices.
## Message Format:
##      DFUN
##      SEQ
##      SFUN
##      NSB
##      XFUN
##      data
##      data:                       bytestring &restofdata  -> data returned to requester
## Protocol Parsing:
##      Parses data from response message and stores in bsap_cnv_rdb.log file
## ------------------------------------------------------------------------------------------------
type RDB_Extension = record {
    DFUN                    : uint8;
    SEQ                     : uint16;
    SFUN                    : uint8;
    NSB                     : uint8;
    XFUN                    : uint16;
    data                    : bytestring &restofdata;  
} &let {
    deliver: bool = $context.flow.proc_bsap_rdb_extension(this);
} &byteorder=littleendian;

## -------------------------------------------BSAP_Unknown-----------------------------------------
## Message Description:
##      BSAP_Unknown is grabbing data that has BSAP comm but no structure defined
## Message Format:
##      data:                       bytestring &restofdata  -> data returned to requester
## Protocol Parsing:
##      Parses data from message and stores in bsap_unknown.log file
## ------------------------------------------------------------------------------------------------
type BSAP_Unknown = record {
    data                    : bytestring &restofdata;
}&let {
    deliver: bool = $context.flow.proc_unknown(this);
} &byteorder=littleendian;
