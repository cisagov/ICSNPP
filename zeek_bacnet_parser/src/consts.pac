## consts.pac
##
## Binpac BACnet Protocol Analyzer - Contains the constants definitions for BACnet
##
## Author:   Stephen Kleinheider
## Contact:  stephen.kleinheider@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
## 
## Commonly Used Acronyms:
##    - BACnet  -> Building Automation and Control Networks
##    - BVLL    -> BACnet Virtual Link Layer
##    - BVLC    -> BACnet Virtual Link Control
##    - NPDU    -> Network Layer Protocol Data Unit
##    - APDU    -> Application Layer Protocol Data Unit
##    - PDU     -> Protocol Data Unit
##    - BDT     -> Broadcast Distribution Table
##    - FDT     -> Foreign Device Table
##    - BBMD    -> BACnet Broadcast Management Device
##    - B/IP    -> BACnet/IP
##    - NSDU    -> Network Service Data Unit
##    - NPCI    -> Network Protocol Control Information
##    - DNET    -> Destination Network Number
##    - DLEN    -> Length of Destination MAC Address
##    - DADR    -> Destination MAC Address
##    - SNET    -> Source Network Number
##    - SLEN    -> Length of Source MAC Address
##    - SADR    -> Source MAC Address
##    - BDT     -> Broadcast Distribution Table

enum named_tags
{
    OPENING = 6,
    CLOSING = 7,
}

############################################################
##################  BVLC Function Codes  ###################
############################################################
enum bvlc_function_codes
{
    BVLC_RESULT                             = 0x00,
    WRITE_BROADCAST_TABLE                   = 0x01,
    READ_BROADCAST_TABLE                    = 0x02,
    READ_BROADCAST_TABLE_ACK                = 0x03,
    FORWARDED_NPDU                          = 0x04,
    REGISTER_FOREIGN_DEVICE                 = 0x05,
    READ_FOREIGN_DEVICE_TABLE               = 0x06,
    READ_FOREIGN_DEVICE_TABLE_ACK           = 0x07,
    DELETE_FOREIGN_DEVICE_TABLE_ENTRY       = 0x08,
    DISTRIBUTE_BROADCAST_TO_NETWORK         = 0x09,
    ORIGINAL_UNICAST_NPDU                   = 0x0A,
    ORIGINAL_BROADCAST_NPDU                 = 0x0B,
    SECURE_BVLL                             = 0x0C,
}

############################################################
###################  NPDU Control Codes  ###################
############################################################
enum npdu_control_codes
{
    NO_CONTROL                              = 0x00,
    EXPECTING_REPLY                         = 0x04,
    CONTROL_SOURCE                          = 0x08,
    CONTROL_DESTINATION                     = 0x20,
    CONTROL_DEST_AND_SOURCE                 = 0x28,
}

############################################################
#######################  APDU Types  #######################
############################################################
enum apdu_types
{
    CONFIRMED_REQUEST                       = 0x00,
    UNCONFIRMED_REQUEST                     = 0x01,
    SIMPLE_ACK                              = 0x02,
    COMPLEX_ACK                             = 0x03,
    SEGMENT_ACK                             = 0x04,
    ERROR_PDU                               = 0x05,
    REJECT_PDU                              = 0x06,
    ABORT_PDU                               = 0x07,
}

############################################################
###############  Confirmed Service Choices  ################
############################################################
enum confirmed_service_choice
{
    ACKNOWLEDGE_ALARM                       = 0x00,
    CONFIRMED_COV_NOTIFICATION              = 0x01,
    CONFIRMED_EVENT_NOTIFICATION            = 0x02,
    GET_ALARM_SUMMARY                       = 0x03,
    GET_ENROLLMENT_SUMMARY                  = 0x04,
    SUBSCRIBE_COV                           = 0x05,
    ATOMIC_READ_FILE                        = 0x06,
    ATOMIC_WRITE_FILE                       = 0x07,
    ADD_LIST_ELEMENT                        = 0x08,
    REMOVE_LIST_ELEMENT                     = 0x09,
    CREATE_OBJECT                           = 0x0A,
    DELETE_OBJECT                           = 0x0B,
    READ_PROPERTY                           = 0x0C,
    READ_PROPERTY_CONDITIONAL               = 0x0D,
    READ_PROPERTY_MULTIPLE                  = 0x0E,
    WRITE_PROPERTY                          = 0x0F,
    WRITE_PROPERTY_MULTIPLE                 = 0x10,
    DEVICE_COMMUNICATION_CONTROL            = 0x11,
    CONFIRMED_PRIVATE_TRANSFER              = 0x12,
    CONFIRMED_TEXT_MESSAGE                  = 0x13,
    REINITIALIZE_DEVICE                     = 0x14,
    VT_OPEN                                 = 0x15,
    VT_CLOSE                                = 0x16,
    VT_DATA                                 = 0x17,
    AUTHENTICATE                            = 0x18,
    REQUEST_KEY                             = 0x19,
    READ_RANGE                              = 0x1A,
    LIFE_SAFETY_OPERATION                   = 0x1B,
    SUBSCRIBE_COV_PROPERTY                  = 0x1C,
    GET_EVENT_INFORMATION                   = 0x1D,
}

############################################################
##############  Unconfirmed Service Choices  ###############
############################################################
enum unconfirmed_service_choice
{
    I_AM                                    = 0x00,
    I_HAVE                                  = 0x01,
    UNCONFIRMED_COV_NOTIFICATION            = 0x02,
    UNCONFIRMED_EVENT_NOTIFICATION          = 0x03,
    UNCONFIRMED_PRIVATE_TRANSFER            = 0x04,
    UNCONFIRMED_TEXT_MESSAGE                = 0x05,
    TIME_SYNCHRONIZATION                    = 0x06,
    WHO_HAS                                 = 0x07,
    WHO_IS                                  = 0x08,
    UTC_TIME_SYNCHRONIZATION                = 0x09,
    WRITE_GROUP                             = 0x0A,
    UNCONFIRMED_COV_NOTIFICATION_MULTIPLE   = 0x0B,
}