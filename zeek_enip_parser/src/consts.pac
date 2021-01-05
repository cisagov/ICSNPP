## consts.pac
##
## Binpac Ethernet/IP (ENIP) Analyzer - Contains the constants definitions for Ethernet/IP and CIP
##
## Author:   Stephen Kleinheider
## Contact:  stephen.kleinheider@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

############################################################
###############  Ethernet/IP Command Codes  ################
############################################################
enum command_codes 
{
    NOP                                 = 0x0000,
    LIST_SERVICES                       = 0x0004,
    LIST_IDENTITY                       = 0x0063,
    LIST_INTERFACES                     = 0x0064,
    REGISTER_SESSION                    = 0x0065,
    UNREGISTER_SESSION                  = 0x0066,
    SEND_RR_DATA                        = 0x006F,
    SEND_UNIT_DATA                      = 0x0070,
    START_DTLS                          = 0x00C8,
    };

############################################################
######  Ethernet/IP Common Packet Format Item Types  #######
############################################################
enum cpf_item_types 
{
    NULL_ADDRESS                        = 0x0000,
    CIP_IDENTITY                        = 0x000C,
    CIP_SECURITY                        = 0x0086,
    ENIP_CAPABILITY                     = 0x0087,
    CONNECTED_ADDRESS                   = 0x00A1,
    CONNECTED_TRANSPORT_DATA            = 0x00B1,
    UNCONNECTED_MESSAGE_DATA            = 0x00B2,
    LIST_SERVICES_RESPONSE              = 0x0100,
    SOCK_ADDR_DATA_ORIG_TO_TARGET       = 0x8000,
    SOCK_ADDR_DATA_TARGET_TO_ORIG       = 0x8001,
    SEQUENCED_ADDRESS_ITEM              = 0x8002,
    UNCONNECTED_MESSAGE_DTLS            = 0x8003,
    # 0x0001 - 0x000B   -> Reserved for legacy usage
    # 0x000D - 0x0085   -> Reserved for legacy usage
    # 0x0088 - 0x0090   -> Reserved for future expansion
    # 0x0091 - 0x0091   -> Reserved for legacy usage
    # 0x0092 - 0x00A0   -> Reserved for future expansion
    # 0x00A2 - 0x00A4   -> Reserved for legacy usage
    # 0x00A5 - 0x00B0   -> Reserved for future expansion
    # 0x00B3 - 0x00FF   -> Reserved for future expansion
    # 0x0101 - 0x010F   -> Reserved for legacy usage
    # 0x0110 - 0x07FF   -> Reserved for future expansion
    # 0x8004 - 0xFFFF   -> Reserved for future expansion
}

############################################################
##################  CIP Common Services  ###################
############################################################
enum cip_common_services 
{
    GET_ATTRIBUTES_ALL                  = 0x01,
    SET_ATTRIBUTES_ALL                  = 0x02,
    GET_ATTRIBUTE_LIST                  = 0x03,
    SET_ATTRIBUTE_LIST                  = 0x04,
    RESET                               = 0x05,
    START                               = 0x06,
    STOP                                = 0x07,
    CREATE                              = 0x08,
    DELETE                              = 0x09,
    MULTIPLE_SERVICE                    = 0x0A,
    APPLY_ATTRIBUTES                    = 0x0D,
    GET_ATTRIBUTE_SINGLE                = 0x0E,
    SET_ATTRIBUTE_SINGLE                = 0x10,
    FIND_NEXT_OBJECT_INSTANCE           = 0x11,
    RESTORE                             = 0x15,
    SAVE                                = 0x16,
    NO_OPERATION                        = 0x17,
    GET_MEMBER                          = 0x18,
    SET_MEMBER                          = 0x18,
    INSERT_MEMBER                       = 0x1A,
    REMOVE_MEMBER                       = 0x1B,
    GROUP_SYNC                          = 0x1C,
    GET_CONNECTION_POINT_MEMBER_LIST    = 0x1D,
    GET_ATTRIBUTES_ALL_RESPONSE         = 0x81,
    GET_ATTRIBUTE_LIST_RESPONSE         = 0x83,
    SET_ATTRIBUTE_LIST_RESPONSE         = 0x84,
    MULTIPLE_SERVICE_RESPONSE           = 0x8A,
    GET_ATTRIBUTE_SINGLE_RESPONSE       = 0x8E,
}