## bacnet-protocol.pac
##
## Binpac BACnet Protocol Analyzer - Defines Protocol Message Formats
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%include consts.pac

###################################################################################################
#####################################  ZEEK CONNECTION DATA  ######################################
###################################################################################################

type BACNET_PDU(is_orig: bool) = record {
    bacnet : BVLC_Header;
} &byteorder=bigendian;

###################################################################################################
##################################  END OF ZEEK CONNECTION DATA  ##################################
###################################################################################################

###################################################################################################
########################################  BVLC PROCESSING  ########################################
###################################################################################################

## ------------------------------------------BVLC-Header-------------------------------------------
## Message Description:
##      BACnet Virtual Link Control (BVLC) Header contains the BVLC functions required to
##      support BACnet/IP directed and broadcast messages
## Message Format:
##      - BVLC Type:        1 byte      -> Always 0x81 for BACnet/IP
##      - BVLC Function:    1 byte      -> Identifies specific function (see consts.pac)
##      - BVLC Length:      2 bytes     -> Length of entire BACnet/IP message in bytes
## Protocol Parsing:
##      Passes BVLC Function to corresponding function type for further processing
## ------------------------------------------------------------------------------------------------
type BVLC_Header = record {
    bvlc_type         : uint8 &enforce(bvlc_type == 0x81);
    bvlc_function     : uint8;
    length            : uint16;
    body             : case bvlc_function of {
        BVLC_RESULT                         -> bvlc_result:                         BVLC_Result;
        WRITE_BROADCAST_TABLE               -> write_broadcast:                     Write_Broadcast_Distribution_Table;
        READ_BROADCAST_TABLE                -> read_broadcast:                      Read_Broadcast_Distribution_Table;
        READ_BROADCAST_TABLE_ACK            -> read_broadcast_ack:                  Read_Broadcast_Distribution_Table_ACK;
        FORWARDED_NPDU                      -> forwarded_npdu:                      Forwarded_NPDU;
        REGISTER_FOREIGN_DEVICE             -> register_foreign_device:             Register_Foreign_Device;
        READ_FOREIGN_DEVICE_TABLE           -> read_foreign_device_table:           Read_Foreign_Device_Table;
        READ_FOREIGN_DEVICE_TABLE_ACK       -> read_foreign_device_table_ack:       Read_Foreign_Device_Table_ACK;
        DELETE_FOREIGN_DEVICE_TABLE_ENTRY   -> delete_foreign_device_table_entry:   Delete_Foreign_Device_Table_Entry;
        DISTRIBUTE_BROADCAST_TO_NETWORK     -> distribute_broadcast_to_network:     Distribute_Broadcast_to_Network;
        ORIGINAL_UNICAST_NPDU               -> original_unicast_npdu:               Original_Unicast_NPDU;
        ORIGINAL_BROADCAST_NPDU             -> broadcast_npdu:                      Original_Broadcast_NPDU;
        SECURE_BVLL                         -> secure_bvll:                         Secure_BVLL;
        default                             -> unknown:                             bytestring &restofdata;
    };
}

## ------------------------------------------BVLC-Result-------------------------------------------
## Message Description:
##      BVLC-Result message provides a mechanism to acknowledge the result of those BVLL service
##      requests that require an acknowledgment, whether successful (ACK) or unsuccessful (NAK).
## Message Format:
##      - BVLC Header:      4 bytes      -> See BVLC_Header
##      - Result Code:      2 bytes      -> Result Code (see bvlc_results in consts.zeek)
## Protocol Parsing:
##      Logs BVLC Function (0x00 for BVLC-Result) and Result Code to bacnet.log
## ------------------------------------------------------------------------------------------------
type BVLC_Result = record {
    result_code     : uint16;
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x00, -1, -1, 0, result_code);
};

## -------------------------------Write-Broadcast-Distribution-Table-------------------------------
## Message Description:
##      Write-Broadcast-Distribution-Table message provides a mechanism for initializing or
##      updating a Broadcast Distribution Table (BDT) in a BACnet Broadcast Management Device.
## Message Format:
##      - BVLC Header       4 bytes             -> See BVLC_Header
##      - BDT Entries:      List of BDT-Entries -> BDT Entries to write (see BDT-Entry) 
## Protocol Parsing:
##      Logs BVLC Function (0x01 for Write-Broadcast-Distribution-Table) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Write_Broadcast_Distribution_Table = record {
    bdt_entries     : BDT_Entry[] &until($input == 0);
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x01, -1, -1, 0, 0);
};

## -------------------------------Read-Broadcast-Distribution-Table--------------------------------
## Message Description:
##      Read-Broadcast-Distribution-Table message provides a mechanism for retrieving the contents
##      of a BBMD's BDT.
## Message Format:
##      - BVLC Header       4 bytes             -> See BVLC_Header
## Protocol Parsing:
##      Logs BVLC Function (0x02 for Read-Broadcast-Distribution-Table) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Read_Broadcast_Distribution_Table = record {
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x02, -1, -1, 0, 0);
};

## -----------------------------Read-Broadcast-Distribution-Table-ACK------------------------------
## Message Description:
##      Read-Broadcast-Distribution-Table-ACK message returns the current contents of a BBMD's BDT
##      to the requester. An empty BDT shall be signified by a list of length zero.
## Message Format:
##      - BVLC Header       4 bytes             -> See BVLC_Header
##      - BDT Entries:      List of BDT-Entries -> BDT Entries (see BDT-Entry)
## Protocol Parsing:
##      Logs BVLC Function (0x03 for Read-Broadcast-Distribution-Table-ACK) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Read_Broadcast_Distribution_Table_ACK = record {
    bdt_entries     : BDT_Entry[] &until($input == 0);
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x03, -1, -1, 0, 0);
};

## -----------------------------------------Forwarded-NPDU-----------------------------------------
## Message Description:
##      Forwarded-NPDU message is used in broadcast messages from a BBMD as well as in messages
##      forwarded to registered foreign devices.
##      Upon receipt of a Forwarded-NPDU with a B/IP Address of Originating Device field whose
##      B/IP address is different from the B/IP address of the sending node, the receiving node
##      shall utilize the contents of that field as the source B/IP address of the sending node.
## Message Format:
##      - BVLC Header   4 bytes     -> See BVLC_Header
##      - bacnet_ip:    4 bytes     -> B/IP Address of Originating Device
##      - bacnet_port:  2 bytes     -> B/IP Port of Originating Device
## Protocol Parsing:
##      Passes BVLC Function (0x04 for Forwarded-NPDU) to NPDU layer for further processing
## ------------------------------------------------------------------------------------------------
type Forwarded_NPDU = record {
    bacnet_ip       : uint32;
    bacnet_port     : uint16;
    npdu            : NPDU_Header(0x04);
}

## ------------------------------------Register-Foreign-Device-------------------------------------
## Message Description:
##      Register-Foreign-Device message allows a foreign device to register with a BBMD for the
##      purpose of receiving broadcast messages.
## Message Format:
##      - BVLC Header:      4 bytes     -> See BVLC_Header
##      - TTL:              2 bytes     -> Time-to-Live in seconds
## Protocol Parsing:
##      Logs BVLC Function (0x05 for Register-Foreign-Device) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Register_Foreign_Device = record {
    ttl             : uint16;
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x05, -1, -1, 0, 0);
};

## -----------------------------------Read-Foreign-Device-Table------------------------------------
## Message Description:
##      Read-Foreign-Device-Table message provides a mechanism for retrieving the contents of a
##      BBMD's FDT.
## Message Format:
##      - BVLC Header:      4 bytes     -> See BVLC_Header
## Protocol Parsing:
##      Logs BVLC Function (0x06 for Read-Foreign-Device-Table) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Read_Foreign_Device_Table = record {
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x06, -1, -1, 0, 0);
};

## ---------------------------------Read-Foreign-Device-Table-ACK----------------------------------
## Message Description:
##      Read-Foreign-Device-Table-ACK message returns the current contents of a BBMD's FDT to the
##      requester.
##      An empty FDT shall be signified by a list of length zero
## Message Format:
##      - BVLC Header:      4 bytes             -> See BVLC_Header
##      - FDT Entries:      List of FDT-Entries -> FDT Entries (see FDT-Entry)
## Protocol Parsing:
##      Logs BVLC Function (0x07 for Read-Foreign-Device-Table-ACK) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Read_Foreign_Device_Table_ACK = record {
    fdt_entries     : FDT_Entry[] &until($input == 0);
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x07, -1, -1, 0, 0);
};

## -------------------------------Delete-Foreign-Device-Table-Entry--------------------------------
## Message Description:
##      Delete-Foreign-Device-Table-Entry message is used to delete an entry from the
##      Foreign-Device-Table.
## Message Format:
##      - BVLC Header:  4 bytes     -> See BVLC_Header
##      - FDT Entry:    FDT_Entry   -> FDT Entry to be deleted
## Protocol Parsing:
##      Logs BVLC Function (0x08 for Delete-Foreign-Device-Table-Entry) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Delete_Foreign_Device_Table_Entry = record {
    fdt_entry         : FDT_Entry;
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x08, -1, -1, 0, 0);
};

## --------------------------------Distribute-Broadcast-to-Network---------------------------------
## Message Description:
##      Distribute-Broadcast-to-Network message provides a mechanism whereby a foreign device may
##      cause a BBMD to broadcast a message on all IP subnets in the BBMD's BDT.
## Message Format:
##      - BVLC Header:  4 bytes     -> See BVLC_Header
## Protocol Parsing:
##      Passes BVLC Function (0x09 for Distribute-Broadcast-to-Network) to NPDU layer for further
##      processing
## ------------------------------------------------------------------------------------------------
type Distribute_Broadcast_to_Network = record {
    npdu             : NPDU_Header(0x09);
}

## -------------------------------------Original-Unicast-NPDU--------------------------------------
## Message Description:
##      Original-Unicast-NPDU message is used to send directed NPDUs to another B/IP device or
##      router.
## Message Format:
##      - BVLC Header:  4 bytes     -> See BVLC_Header
## Protocol Parsing:
##      Passes BVLC Function (0x0A for Original-Unicast-NPDU) to NPDU layer for further processing
## ------------------------------------------------------------------------------------------------
type Original_Unicast_NPDU = record {
    npdu             : NPDU_Header(0x0A);
}

## ------------------------------------Original-Broadcast-NPDU-------------------------------------
## Message Description:
##      Original-Broadcast-NPDU is used by B/IP devices and routers which are not foreign devices
##      to broadcast NPDUs on a B/IP network.
## Message Format:
##      - BVLC Header:  4 bytes     -> See BVLC_Header
## Protocol Parsing:
##      Passes BVLC Function (0x0B for Original-Broadcast-NPDU) to NPDU layer for further processing
## ------------------------------------------------------------------------------------------------
type Original_Broadcast_NPDU = record {
    npdu             : NPDU_Header(0x0B);
}

## ------------------------------------------Secure-BVLL-------------------------------------------
## Message Description:
##      Secure-BVLL message is used to secure BVLL messages that do not contain NPDUs.
## Message Format:
##      - BVLC Header:      4 bytes         -> See BVLC_Header
##      - Security Wrapper: Variable Length -> BVLL to be secured
## Protocol Parsing:
##      Logs BVLC Function (0x0C for Secure-BVLL) to bacnet.log
## ------------------------------------------------------------------------------------------------
type Secure_BVLL = record {
    data             : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.process_bacnet_header(0x0C, -1, -1, 0, 0);
};

## -------------------------------------------BDT-Entry--------------------------------------------
## Message Description:
##      Broadcast Distribution Table (BDT) entry
## Message Format:
##      - BDT IP:           4 bytes     -> broadcast distribution B/IP Address
##      - BDT Port:         2 byte      -> broadcast distribution B/IP Port
##      - BDT Mask:         4 bytes     -> broadcast distribution mask
## Protocol Parsing:
##      Continue with BVLC processing
## ------------------------------------------------------------------------------------------------
type BDT_Entry = record {
    bdt_ip          : uint32;
    bdt_port        : uint16;
    bdt_mask        : uint32;
}

## -------------------------------------------FDT-Entry--------------------------------------------
## Message Description:
##      Foreign Device Table (FDT) entry
## Message Format:
##      - FDT IP:           4 bytes     -> foreign device B/IP Address
##      - FDT Port:         2 byte      -> foreign device B/IP Port
##      - TTL:              2 bytes     -> time to live at time of registration
##      - Remaining TTL:    2 bytes     -> remaining time to live
## Protocol Parsing:
##      Continue with BVLC processing
## ------------------------------------------------------------------------------------------------
type FDT_Entry = record {
    fdt_ip          : uint32;
    fdt_port        : uint16;
    ttl             : uint16;
    remaining_ttl   : uint16;
}

###################################################################################################
####################################  END OF BVLC PROCESSING  #####################################
###################################################################################################


###################################################################################################
########################################  NPDU PROCESSING  ########################################
###################################################################################################

## ------------------------------------------NPDU-Header-------------------------------------------
## Message Description:
##      The NPDU provides the means by which messages can be relayed from one BACnet network to
##      another, regardless of the BACnet data link technology in use on that network.
## Message Format:
##      - BACnet Protocol Version:     1 byte   -> Current version = 1
##      - NPDU Control Information:    1 bytes  -> Indicates presence or absence of NPCI fields
##          + Bit 7 -> NSDU Contains
##            - 0: NSDU contains a BACnet APDU, Message_Type field is absent
##            - 1: NSDU contains a network layer message, Message_Type field is present
##          + Bit 6 -> Reserved
##            - Reserved. Should be set to 0
##          + Bit 5 -> Destination Specifier
##            - 0: DNET, DLEN, DADR, and Hop Count absent
##            - 1: DNET, DLEN, DADR, and Hop Count present (See NPDU_Destination)
##          + Bit 4 -> Reserved
##            - Reserved. Should be set to 0
##          + Bit 3 -> Source Specifier
##            - 0: SNET, SLEN, SADR absent
##            - 1: SNET, SLEN, SADR present (See NPDU_Source)
##          + Bit 2 -> Expecting Reply
##            - 0: BACnet-Confirmed-Request-PDU, a segment of a BACnet-ComplexACK-PDU, or a
##                 network layer message expecting a reply is present.
##            - 1: other than the messages listed above, a network layer message expecting a
##                 reply is present.
##          + Bit 1,0 -> Priority
##            - 00: Normal Message
##            - 01: Urgent Message
##            - 10: Critical Equipment Message
##            - 11: Life Safety Message
## Protocol Parsing:
##      Passes BVLC Function to APDU for further processing
## ------------------------------------------------------------------------------------------------
type NPDU_Header(bvlc_function: uint8) = record {
    protocol_version    : uint8;
    npdu_control        : uint8;
    destination         : case ((npdu_control & 0x20) >> 5) of {
        1       -> destination_exists:  NPDU_Destination;
        default -> no_destination:      empty;
    };
    source              : case ((npdu_control & 0x08) >> 3) of {
        1       -> source_exists:       NPDU_Source;
        default -> no_source:           empty;
    };
    hop_count           : case ((npdu_control & 0x20) >> 5) of {
        1       -> hop_count_value:     uint8;
        default -> no_hop_count:        empty;
    };
    apdu                : APDU_Header(bvlc_function);
}

## ----------------------------------------NPDU-Destination----------------------------------------
## Message Description:
##      Process NPDU destination fields
## Message Format:
##      - DNET:     2 bytes             -> Ultimate Destination Network Number
##      - DLEN:     1 byte              -> Length of Ultimate Destination MAC layer address
##        + Value of 0 indicates broadcast on the destination network
##      - DADR:     variable length     -> Ultimate Destination MAC layer address
## Protocol Parsing:
##      Continue with NPDU processing
## ------------------------------------------------------------------------------------------------
type NPDU_Destination = record {
    DNET        : uint16;
    DLEN        : uint8;
    DADR        : bytestring &length = DLEN;
}

## ------------------------------------------NPDU-Source-------------------------------------------
## Message Description:
##      Process NPDU source fields
## Message Format:
##      - SNET:     2 bytes     -> Original Source Network Number
##      - SLEN:     1 byte      -> Length of Original Source MAC layer address
##      - SADR:     Variable    -> Original Source MAC layer address
## Protocol Parsing:
##      Continue with NPDU processing
## ------------------------------------------------------------------------------------------------
type NPDU_Source = record {
    SNET        : uint16;
    SLEN        : uint8;
    SADR        : bytestring &length = SLEN;
}


###################################################################################################
####################################  END OF NPDU PROCESSING  #####################################
###################################################################################################


###################################################################################################
########################################  APDU PROCESSING  ########################################
###################################################################################################

## ------------------------------------------APDU-Header-------------------------------------------
## Message Description:
##      The APDU provides the application data for BACnet protocol.
## Message Format:
##      - Choice Tag: Choice Tag of APDU header
##          + Bit 7-4   -> PDU Type
##          + Bit 3-0   -> Variable (depends on PDU type)
## Protocol Parsing:
##      Passes Choice Tag and BVLC Function to APDU for further processing
## ------------------------------------------------------------------------------------------------
type APDU_Header(bvlc_function: uint8) = record {
    choice_tag      : uint8;
    body            : case (choice_tag >> 4) of {
        CONFIRMED_REQUEST   -> confirmed_request:   Confirmed_Request_PDU(choice_tag,bvlc_function);
        UNCONFIRMED_REQUEST -> unconfirmed_request: Unconfirmed_Request_PDU(choice_tag,bvlc_function);
        SIMPLE_ACK          -> simple_ack:          Simple_ACK_PDU(choice_tag, bvlc_function);
        COMPLEX_ACK         -> complex_ack:         Complex_ACK_PDU(choice_tag, bvlc_function);
        SEGMENT_ACK         -> segment_ack:         Segment_ACK_PDU(choice_tag,bvlc_function);
        ERROR_PDU           -> error_pdu:           Error_PDU(choice_tag,bvlc_function);
        REJECT_PDU          -> reject_pdu:          Reject_PDU(choice_tag,bvlc_function);
        ABORT_PDU           -> abort_pdu:           Abort_PDU(choice_tag,bvlc_function);
        default             -> unknown:             bytestring &restofdata;
    };
}

## -------------------------------------Confirmed-Request-PDU--------------------------------------
## Message Description:
##      Confirmed-Request-PDU is used to convey the information contained in confirmed service
##      request primitives.
## Message Format:
##      - Choice Tag:           1 byte          -> Passed from APDU_Header
##          + Bits 7-4  -> PDU Type
##            - Always 0 for Confirmed Requests
##          + Bit 3     -> SEG
##            - 0: Unsegmented Request
##            - 1: Segmented Request
##          + Bit 2     -> MOR
##            - 0: No More Segments Follow
##            - 1: More Segments Follow
##          + Bit 1     -> SA
##            - 0: Segmented Response not accepted
##            - 1: Segmented Response accepted
##          + Bit 0     -> Unused
##            - Always 0 for Confirmed Requests
##      - Size Information:     1 byte          -> Contains Max Segs and Max Resp
##          + Bit 7     -> Unused
##            - Always 0 for Confirmed Requests
##          + Bit 6-4   -> Max Segs (Number of response segments accepted)
##            - 000: Unspecified number of segments accepted
##            - 001: 2 segments accepted
##            - 010: 4 segments accepted
##            - 011: 8 segments accepted
##            - 100: 16 segments accepted
##            - 101: 32 segments accepted
##            - 110: 64 segments accepted
##            - 111: Greater than 64 segments accepted
##          + Bit 3-0   -> Max Resp (Size of Maximum APDU accepted)
##            - 0000: Up to MinimumMessageSize (50 bytes)
##            - 0001: Up to 128 bytes
##            - 0010: Up to 206 bytes (fits in a LonTalk frame)
##            - 0011: Up to 480 bytes (fits in an ARCNET frame)
##            - 0100: Up to 1024 bytes
##            - 0101: Up to 1476 bytes (fits in an Ethernet frame)
##            - Other: Reserved by ASHRAE
##      - Invoke ID:            1 byte          -> Integer in the range 0-255 generated by the device
##                                                 issuing the service request. It is unique for all
##                                                 outstanding confirmed request APDUs generated by
##                                                 the device.
##      - Sequence Number:      1 byte          -> Identifies the segment of a segmented request
##          + Only present if SEG = 1
##      - Proposed Window Size: 1 byte          -> Specifies maximum number of message segments the
##                                                 sender is able to send before waiting for a
##                                                 Segment-ACK-PDU
##          + Only present if SEG = 1
##      - Service Choice:       1 byte          -> See confirmed_service_choice in consts.pac
##      - Service Requests:     List of Tags    -> List of BACnet Tags (See BACnet_Tag)
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Service Choice, and Invoke ID to bacnet.log
##      Passes Confirmed Request Tags to corresponding analyzer in bacnet_analyzer.pac
## ------------------------------------------------------------------------------------------------
type Confirmed_Request_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    size_information        : uint8;
    invoke_id               : uint8;
    sequence_num            : case ((choice_tag & 0x8) >> 3) of {
        1       -> sequence_num_value:      uint8;
        default -> no_sequence_num:         empty;
    };
    proposed_window         : case ((choice_tag & 0x8) >> 3) of {
        1       -> proposed_window_value:   uint8;
        default -> no_proposed_window:      empty;
    };
    service_choice          : uint8;
    service_request_tags    : BACnet_Tag[] &until($input == 0);
} &let {
    deliver: bool = case service_choice of {
        ACKNOWLEDGE_ALARM               -> $context.flow.process_acknowledge_alarm(service_request_tags);
        CONFIRMED_COV_NOTIFICATION      -> $context.flow.process_confirmed_cov_notification(service_request_tags);
        CONFIRMED_EVENT_NOTIFICATION    -> $context.flow.process_confirmed_event_notification(service_request_tags);
        GET_ALARM_SUMMARY               -> $context.flow.process_get_alarm_summary(service_request_tags);
        GET_ENROLLMENT_SUMMARY          -> $context.flow.process_get_enrollment_summary(service_request_tags);
        SUBSCRIBE_COV                   -> $context.flow.process_subscribe_cov(service_request_tags);
        ATOMIC_READ_FILE                -> $context.flow.process_atomic_read_file(service_request_tags);
        ATOMIC_WRITE_FILE               -> $context.flow.process_atomic_write_file(service_request_tags);
        ADD_LIST_ELEMENT                -> $context.flow.process_add_list_element(service_request_tags);
        REMOVE_LIST_ELEMENT             -> $context.flow.process_remove_list_element(service_request_tags);
        CREATE_OBJECT                   -> $context.flow.process_create_object(service_request_tags);
        DELETE_OBJECT                   -> $context.flow.process_delete_object(service_request_tags);
        READ_PROPERTY                   -> $context.flow.process_read_property(service_request_tags);
        READ_PROPERTY_CONDITIONAL       -> false; # Removed in Version 1 Revision 12
        READ_PROPERTY_MULTIPLE          -> $context.flow.process_read_property_multiple(service_request_tags);
        WRITE_PROPERTY                  -> $context.flow.process_write_property(service_request_tags);
        WRITE_PROPERTY_MULTIPLE         -> $context.flow.process_write_property_multiple(service_request_tags);
        DEVICE_COMMUNICATION_CONTROL    -> $context.flow.process_device_communication_control(service_request_tags);
        CONFIRMED_PRIVATE_TRANSFER      -> $context.flow.process_confirmed_private_transfer(service_request_tags);
        CONFIRMED_TEXT_MESSAGE          -> $context.flow.process_confirmed_text_message(service_request_tags);
        REINITIALIZE_DEVICE             -> $context.flow.process_reinitialize_device(service_request_tags);
        VT_OPEN                         -> $context.flow.process_vt_open(service_request_tags);
        VT_CLOSE                        -> $context.flow.process_vt_close(service_request_tags);
        VT_DATA                         -> $context.flow.process_vt_data(service_request_tags);
        AUTHENTICATE                    -> false; # Removed in Version 1 Revision 11
        REQUEST_KEY                     -> false; # Removed in Version 1 Revision 11
        READ_RANGE                      -> $context.flow.process_read_range(service_request_tags);
        LIFE_SAFETY_OPERATION           -> $context.flow.process_life_safety_operation(service_request_tags);
        SUBSCRIBE_COV_PROPERTY          -> $context.flow.process_subscribe_cov_property(service_request_tags);
        GET_EVENT_INFORMATION           -> $context.flow.process_get_event_information(service_request_tags);
        default                         -> false;
    };
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, service_choice, invoke_id, 0);
};

## ------------------------------------Unconfirmed-Request-PDU-------------------------------------
## Message Description:
##      Unconfirmed-Request-PDU is used to convey the information contained in unconfirmed service
##      request primitives.
## Message Format:
##      - Choice Tag:       1 byte          -> Passed from APDU_HeaderRequests
##          + Bits 7-4 -> PDU Type
##            - Always 1 for Unconfirmed Requests
##          + Bits 3-0 -> Unused
##            - Always 0 for Unconfirmed Requests
##      - Service Choice:   1 byte          -> See unconfirmed_service_choice in consts.pac
##      - Service Requests: List of Tags    -> List of BACnet Tags (See BACnet_Tag)
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, and Service Choice to bacnet.log
##      Passes Unconfirmed Request Tags to corresponding analyzer in bacnet_analyzer.pac
## ------------------------------------------------------------------------------------------------
type Unconfirmed_Request_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    service_choice              : uint8;
    service_request_tags        : BACnet_Tag[] &until($input == 0);
} &let {
    deliver: bool = case service_choice of {
        I_AM                                    -> $context.flow.process_i_am(service_request_tags);
        I_HAVE                                  -> $context.flow.process_i_have(service_request_tags);
        UNCONFIRMED_COV_NOTIFICATION            -> $context.flow.process_unconfirmed_cov_notification(service_request_tags);
        UNCONFIRMED_EVENT_NOTIFICATION          -> $context.flow.process_unconfirmed_event_notification(service_request_tags);
        UNCONFIRMED_PRIVATE_TRANSFER            -> $context.flow.process_unconfirmed_private_transfer(service_request_tags);
        UNCONFIRMED_TEXT_MESSAGE                -> $context.flow.process_unconfirmed_text_message(service_request_tags);
        TIME_SYNCHRONIZATION                    -> $context.flow.process_time_synchronization(service_request_tags);
        WHO_HAS                                 -> $context.flow.process_who_has(service_request_tags);
        WHO_IS                                  -> $context.flow.process_who_is(service_request_tags);
        UTC_TIME_SYNCHRONIZATION                -> $context.flow.process_utc_time_synchronization(service_request_tags);
        WRITE_GROUP                             -> $context.flow.process_write_group(service_request_tags);
        UNCONFIRMED_COV_NOTIFICATION_MULTIPLE   -> $context.flow.process_unconfirmed_cov_notification_multiple(service_request_tags);
        default -> false;
    };
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, service_choice, 0, 0);
};

## -----------------------------------------Simple-ACK-PDU-----------------------------------------
## Message Description:
##      SimpleACK-PDU is used to convey the information contained in a service response primitive
##      that contains no other information except that the service request was successfully
##      carried out
## Message Format:
##      - Choice Tag:        1 byte -> Passed from APDU_Header
##          + Bits 7-4 -> PDU Type
##            - Always 2 for Simple ACK
##          + Bits 3-0 -> Unused
##            - Always 0 for Simple ACK
##      - Invoke ID:        1 byte  -> Invoke ID contained in the request being acknowledged
##      - Service Choice:   1 byte  -> See confirmed_service_choice in consts.pac
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Service Choice, and Invoke ID to bacnet.log
## ------------------------------------------------------------------------------------------------
type Simple_ACK_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    invoke_id       : uint8;
    service_choice  : uint8;
} &let {
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, service_choice, invoke_id, 0);
};

## ----------------------------------------Complex-ACK-PDU-----------------------------------------
## Message Description:
##      ComplexACK-PDU is used to convey the information contained in a service response primitive
##      that contains information in addition to the fact that the service request was
##      successfully carried out.
## Message Format:
##      - Choice Tag:           1 byte          -> Passed from APDU_Header
##          + Bits 7-4  -> PDU Type
##            - Always 3 for Complex ACK
##          + Bit 3     -> SEG
##            - 0: Unsegmented Request
##            - 1: Segmented Request
##          + Bit 2     -> MOR
##            - 0: No More Segments Follow
##            - 1: More Segments Follow
##          + Bit 1     -> SA
##            - 0: Segmented Response not accepted
##            - 1: Segmented Response accepted
##          + Bit 0     -> Unused
##            - Always 0 for Complex ACK
##      - Invoke ID:            1 byte          -> Invoke ID contained in the request being
##                                                 acknowledged
##      - Sequence Number:      1 byte          -> Identifies the segment of a segmented request
##          + Only present if SEG = 1
##      - Proposed Window Size: 1 byte          -> Specifies maximum number of message segments the
##                                                 sender is able to send before waiting for a
##                                                 Segment-ACK-PDU
##          + Only present if SEG = 1
##      - Service Choice:       1 byte          -> See confirmed_service_choice in consts.pac
##      - Service ACK:          List of Tags    -> List of BACnet Tags (See BACnet_Tag)
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Service Choice, and Invoke ID to bacnet.log
##      Passes Complex ACK Tags to corresponding analyzer in bacnet_analyzer.pac
## ------------------------------------------------------------------------------------------------
type Complex_ACK_PDU(choice_tag: uint8, bvlc_function: uint8)   = record {
    invoke_id           : uint8;
    sequence_num        : case ((choice_tag & 0x8) >> 3) of {
        1       -> sequence_num_value:      uint8;
        default -> no_sequence_num:         empty;
    };
    proposed_window     : case ((choice_tag & 0x8) >> 3) of {
        1       -> proposed_window_value:   uint8;
        default -> no_proposed_window:      empty;
    };
    service_choice      : uint8;
    service_ack_tags    : BACnet_Tag[] &until($input == 0);
} &let {
    deliver: bool = case service_choice of {
        GET_ALARM_SUMMARY               -> $context.flow.process_get_alarm_summary_ack(service_ack_tags);
        GET_ENROLLMENT_SUMMARY          -> $context.flow.process_get_enrollment_summary_ack(service_ack_tags);
        ATOMIC_READ_FILE                -> $context.flow.process_atomic_read_file_ack(service_ack_tags);
        ATOMIC_WRITE_FILE               -> $context.flow.process_atomic_write_file_ack(service_ack_tags);
        CREATE_OBJECT                   -> $context.flow.process_create_object_ack(service_ack_tags);
        READ_PROPERTY                   -> $context.flow.process_read_property_ack(service_ack_tags);
        READ_PROPERTY_CONDITIONAL       -> false; # Removed in Version 1 Revision 12
        READ_PROPERTY_MULTIPLE          -> $context.flow.process_read_property_multiple_ack(service_ack_tags);
        CONFIRMED_PRIVATE_TRANSFER      -> $context.flow.process_confirmed_private_transfer_ack(service_ack_tags);
        VT_OPEN                         -> $context.flow.process_vt_open_ack(service_ack_tags);
        VT_DATA                         -> $context.flow.process_vt_data_ack(service_ack_tags);
        AUTHENTICATE                    -> false; # Removed in Version 1 Revision 11
        REQUEST_KEY                     -> false; # Removed in Version 1 Revision 11
        READ_RANGE                      -> $context.flow.process_read_range_ack(service_ack_tags);
        GET_EVENT_INFORMATION           -> $context.flow.process_get_event_information_ack(service_ack_tags);
        default                         -> false;
    };
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, service_choice, invoke_id, 0);
};

## ----------------------------------------Segment-ACK-PDU-----------------------------------------
## Message Description:
##      SegmentACK-PDU is used to acknowledge the receipt of one or more APDUs containing portions
##      of a segmented message. It may also request the next segment or segments of the segmented
##       message.
## Message Format:
##      - Choice Tag:           1 byte  -> Passed from APDU_Header
##          + Bits 7-4  -> PDU Type
##            - Always 4 for Segment ACK PDU
##          + Bits 3-2  -> Unused
##            - Always 0 for Segment ACK PDU
##          + Bit 1     -> NAK (Negative-ACK)
##            - 0: Normal Acknowledgment, Segment received in order
##            - 1: Negative Acknowledgment, Segment received out of order
##          + Bit 0     -> SERVER
##            - 0: Segment ACK PDU was sent by client
##            - 1: Segment ACK PDU was sent by server
##      - Original Invoke ID:   1 byte  -> Invoke ID contained in the segment being acknowledged
##      - Sequence Number:      1 byte  -> Sequence number of a previous received segment
##      - Actual Window Size:   1 byte  -> Number of message segments receiver will accept before
##                                         sending another Segment ACK
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Service Choice, and Invoke ID to bacnet.log
## ------------------------------------------------------------------------------------------------
type Segment_ACK_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    invoke_id           : uint8;
    sequence_num        : uint8;
    actual_window_size  : uint8;
} &let {
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, -1, invoke_id, 0);
};

## -------------------------------------------Error-PDU--------------------------------------------
## Message Description:
##      Error-PDU is used to convey the information contained in a service response primitive
##      that indicates the reason why a previous confirmed service request failed either in its
##      entirety or only partially.
## Message Format:
##      - Choice Tag:        1 byte     -> Passed from APDU_Header
##          + Bits 7-4 -> PDU Type
##            - Always 5 for Error PDU
##          + Bits 3-0 -> Unused
##            - Always 0 for Error PDU
##      - Invoke ID:        1 byte      -> Invoke ID contained in the confirmed service request to
##                                         which the error is a response.
##      - Service Choice:   1 byte      -> See confirmed_service_choice in consts.pac
##      - Error Class:      BACnet_Tag  -> Category of Error
##      - Error Code:       BACnet_Tag  -> Description of error (see error_codes in consts.zeek)
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Service Choice, Invoke ID, and Error Code to bacnet.log
## ------------------------------------------------------------------------------------------------
type Error_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    invoke_id       : uint8;
    service_choice  : uint8;
    error_class     : BACnet_Tag;
    error_code      : BACnet_Tag;
} &let {
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, service_choice, invoke_id, error_code.tag_data[0]);
};

## -------------------------------------------Reject-PDU-------------------------------------------
## Message Description:
##      Reject-PDU is used to reject a received confirmed request APDU based on syntactical
##      flaws or other protocol errors that prevent the APDU from being interpreted or the
##      requested service from being provided.
## Message Format:
##      - Choice Tag:       1 byte  -> Passed from APDU_Header
##          + Bits 7-4 -> PDU Type
##            - Always 6 for Reject PDU
##          + Bits 3-0 -> Unused
##            - Always 0 for Reject PDU
##      - Invoke ID:        1 byte  -> Invoke ID of the PDU being rejected
##      - Reject Reason:    1 byte  -> See reject_reasons in consts.zeek
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Invoke ID, and Reject Reason to bacnet.log
## ------------------------------------------------------------------------------------------------
type Reject_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    invoke_id       : uint8;
    reject_reason   : uint8;
} &let {
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, -1, invoke_id, reject_reason);
};

## -------------------------------------------Abort-PDU--------------------------------------------
## Message Description:
##      Abort-PDU is used to terminate a transaction between two peers.
## Message Format:
##      - Choice Tag:       1 byte  -> Passed from APDU_Header
##          + Bits 7-4  -> PDU Type
##            - Always 7 for Abort PDU
##          + Bits 3-1  -> Unused
##            - Always 0 for Abort PDU
##          + Bit 0     -> SERVER
##            - 0: Abort was sent by client
##            - 1: Abort was sent by server
##      - Invoke ID:        1 byte  -> Invoke ID of the transaction being aborted
##      - Abort Reason:     1 byte  -> See abort_reasons in consts.zeek
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Invoke ID, and Abort Reason to bacnet.log
## ------------------------------------------------------------------------------------------------
type Abort_PDU(choice_tag: uint8, bvlc_function: uint8) = record {
    invoke_id       : uint8;
    abort_reason    : uint8;
} &let {
    pdu_type: uint8 = choice_tag >> 4;
    overview: bool = $context.flow.process_bacnet_header(bvlc_function, pdu_type, -1, invoke_id, abort_reason);
};

###################################################################################################
####################################  END OF APDU PROCESSING  #####################################
###################################################################################################


###################################################################################################
######################################  APDU TAG PROCESSING  ######################################
###################################################################################################

## -------------------------------------------BACnet_Tag-------------------------------------------
## Message Description:
##      BACnet Tags are used to convey the service parameter data for BACnet APDUs
## Message Format:
##      - Tag Header:    1 byte     -> Header for tag identifying tag number, class, and length
##          + Bits 7-4 -> Tag Number
##            - 0-14: Tag number
##            - 15: Tag number is located in an additional byte (see Extended_Tag_Number)
##          + Bit 3 -> Tag Class
##            - 0: Application Tag
##            - 1: Context Tag
##          + Bit 2-0 -> Tag Length
##            - 0-4: Length of Tag data
##            - 5: Length of Tag data is an additional byte(s) (See Extended_Tag_Length)
##            - 6: Opening Tag (Length = 0)
##            - 7: Closing Tag (Length = 0)
##      - Tag Data:     Tag_Length  -> Data contained in tag
## Protocol Parsing:
##      Logs BVLC Function, PDU Type, Invoke ID, and Abort Reason to bacnet.log
## ------------------------------------------------------------------------------------------------
type BACnet_Tag = record {
    tag_header      : uint8;
    tag_number      : case (tag_header >> 4) of {
        15      -> extended_num : Extended_Tag_Number;
        default -> normal_num   : empty;
    };
    length_field    : case (tag_header & 0x07) of {
        5       ->  extended_length: Extended_Tag_Length;
        default ->  normal: empty;
    };
    tag_data        : bytestring &length = tag_length;
} &let {
    tag_num:    uint8   = case(tag_header >> 4) of {
        15      -> extended_num.tag_num;
        default -> tag_header >> 4;
    };
    tag_class:  uint8   = (tag_header >> 3) & 1;
    tag_length: uint8   = case(tag_header & 0x07) of {
        5             -> extended_length.length;
        OPENING       -> 0;
        CLOSING       -> 0;
        default -> tag_header & 0x07;
    };
    named_tag: uint8   = tag_header & 0x07;
};

## --------------------------------------Extended_Tag_Number---------------------------------------
## Message Description:
##      Process BACnet Tag Numbers from 15-254 (inclusive)
## Message Format:
##      - tag_num       1 byte      -> BACnet Tag number
## Protocol Parsing:
##      Continue with BACnet Tag processing
## ------------------------------------------------------------------------------------------------
type Extended_Tag_Number = record {
    tag_num     : uint8;
}

## --------------------------------------Extended_Tag_Length---------------------------------------
## Message Description:
##      Process BACnet Tag Length > 4
## Message Format:
##      - extended:    1 byte       -> Integer representing how to interpret length
##          + extended < 254:   BACnet Tag Length = value of extended
##          + extended == 254:  BACnet Tag Length = next 2 bytes
##          + extended == 255:  BACnet Tag Length = next 4 bytes
## Protocol Parsing:
##      Continue with BACnet Tag processing
## ------------------------------------------------------------------------------------------------
type Extended_Tag_Length = record {
    extended        : uint8;
    extended_field  : case (extended) of {
        254     ->  extended_1: uint16;
        255     ->  extended_2: uint32;
        default ->  normal: empty;
    };
} &let {
    length     = case(extended) of {
        254     ->  extended_1;
        255     ->  extended_2;
        default ->  extended;
    };
};

###################################################################################################
##################################  END OF APDU TAG PROCESSING  ###################################
###################################################################################################