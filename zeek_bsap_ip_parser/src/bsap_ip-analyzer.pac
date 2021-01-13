## bsap_ip-analyzer.pac
##
## Binpac BSAP_IP Protocol Analyzer - Defines BSAPIP analyzer events.
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    extern uint8 FuncType;
    extern uint8 AppFuncCode;
    extern uint32 ResponseId;
    extern uint32 MessageId;
    void setFunc(uint8 appfunc);
    void setResponseId(uint8 function, uint32 ResponseSeqID, uint32 MessageSeqID);
    uint32 checkResponse(uint32 Responder);
    uint32 getResponseID();
    uint32 getMessageID();
    uint8 getAppFunc();
%}

%code{
    uint8 FuncType = 0xFF;
    uint8 AppFuncCode = 0xFF;
    uint32 ResponseId = 0;
    uint32 MessageId = 0;

    void setFunc(uint8 func)
    {
        FuncType = func;
    }
    void setResponseId(uint8 function, uint32 ResponseSeqID, uint32 MessageSeqID)
    {
        AppFuncCode = function;
        ResponseId = ResponseSeqID;
        MessageId = MessageSeqID;
    }

    uint32 checkResponse(uint32 Responder)
    {
        if(ResponseId == Responder)
        {
            MessageId = 0;
            ResponseId = 0;
            return FuncType + 0x50;
        }
        else
        {
            return ResponseId;
        }

    }

    uint32 getResponseID()
    {
        return ResponseId;
    }

    uint32 getMessageID()
    {
        return MessageId;
    }

    uint8 getAppFunc()
    {
        return AppFuncCode;
    }
%}

refine flow BSAP_IP_Flow += {

    ###############################################################################################
    ###########################  Process data for bsapip_header event  ############################
    ###############################################################################################
    function proc_bsap_ip_message(bsapip_header: BSAP_IP_PDU): bool
        %{  
            BifEvent::generate_bsapip_header(connection()->bro_analyzer(),
                                             connection()->bro_analyzer()->Conn(),
                                             is_orig(),
                                             ${bsapip_header.header.id},
                                             ${bsapip_header.header.Num_Messages},
                                             ${bsapip_header.header.Message_Func});
            return true;
      %}

    ###############################################################################################
    ######################  Process data for proc_bsap_request_header event  ######################
    ###############################################################################################
    function proc_bsap_request_header(bsap_request_header: BSAP_Request_Header): bool
      %{
            setResponseId(${bsap_request_header.app_func_code},${bsap_request_header.sequence},${bsap_request_header.message_seq});

            if( :: bsap_request_header)
            {
                BifEvent::generate_bsap_request_header(connection()->bro_analyzer(),
                                                       connection()->bro_analyzer()->Conn(),
                                                       ${bsap_request_header.response_seq},
                                                       ${bsap_request_header.message_seq},
                                                       ${bsap_request_header.data_length},
                                                       ${bsap_request_header.header_size},
                                                       ${bsap_request_header.sequence},
                                                       ${bsap_request_header.app_func_code});
            }
            return true;
      %}

    ###############################################################################################
    ########################  Process data for proc_bsap_rdb_request event  #######################
    ###############################################################################################
    function proc_bsap_rdb_request(bsap_rdb_request: RDB_Request): bool
      %{
            uint32 message_id = 0, response_id = 0;
            setFunc(${bsap_rdb_request.func_code});

            response_id = getResponseID();
            message_id = getMessageID();

            if( ::bsapip_rdb_request )
            {
                BifEvent::generate_bsapip_rdb_request(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      response_id,
                                                      message_id,
                                                      ${bsap_rdb_request.node_status},
                                                      ${bsap_rdb_request.func_code},
                                                      bytestring_to_val(${bsap_rdb_request.data}));
            }
            return true;
      %}

    ###############################################################################################
    #########################  Process data for proc_bsap_response event  #########################
    ###############################################################################################
    function proc_bsap_response(bsap_response: BSAP_Response): bool
       %{
            uint32 response_status = 0;
            uint32 app_code = 0;

            app_code = getAppFunc();
            response_status = checkResponse(${bsap_response.response_seq});

            switch(app_code)
            {
                case RDB:
                    if( ::bsapip_rdb_response )
                    {
                       BifEvent::generate_bsapip_rdb_response(connection()->bro_analyzer(),
                                                              connection()->bro_analyzer()->Conn(),
                                                              ${bsap_response.message_seq},
                                                              ${bsap_response.response_seq},
                                                              ${bsap_response.data_length},
                                                              ${bsap_response.header_size},
                                                              ${bsap_response.sequence},
                                                              response_status,
                                                              ${bsap_response.resp_status},
                                                              bytestring_to_val(${bsap_response.data}));
                    }
                    break;
            }
            return true;
       %}

    ###############################################################################################
    ############################  Process data for proc_unknown event  ############################
    ###############################################################################################
    function proc_unknown(bsap_unknown: BSAPIP_Unknown): bool
        %{
            if( ::bsapip_unknown )
            {
               BifEvent::generate_bsapip_unknown(connection()->bro_analyzer(),
                                                 connection()->bro_analyzer()->Conn(),
                                                 bytestring_to_val(${bsap_unknown.data}));
            }
            return true;
        %}
};
