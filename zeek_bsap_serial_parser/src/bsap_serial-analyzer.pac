## bsap_serial-analyzer.pac
##
## Binpac BSAP_SERIAL Analyzer - Defines BSAP analyzer events.
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
    extern uint8 setFlag;
    void setFunc(uint8 appfunc);
    void setResponseId(uint8 function, uint32 ResponseSeqID);
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
    uint8 setFlag = 0;

    void setFunc(uint8 func)
    {
        FuncType = func;
    }
    void setResponseId(uint8 function, uint32 ResponseSeqID)
    {
        if(setFlag == 0)
        {
            AppFuncCode = function;
            MessageId = ResponseSeqID; // this is requester
            setFlag = 1;
        }
        else
        {
            ResponseId = ResponseSeqID; // this is responder
            setFlag = 0;
        }
    }

    uint32 checkResponse(uint32 Responder)
    {
        if(MessageId == Responder)
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


refine flow BSAP_SERIAL_Flow += {

    function proc_bsap_serial_message(bsap_header: BSAP_SERIAL_PDU): bool
        %{  
            return true;
        %}

    ###############################################################################################
    #########################  Process data for bsap_local_header event  ##########################
    ###############################################################################################
    function proc_bsap_local_header(bsap_local_header: BSAP_Local_Header): bool
      %{
            if( ::bsap_local_header)
            {
                setResponseId(${bsap_local_header.DFUN}, ${bsap_local_header.SEQ});

                BifEvent::generate_bsap_local_header(connection()->bro_analyzer(),
                                                     connection()->bro_analyzer()->Conn(),
                                                     ${bsap_local_header.SER},
                                                     ${bsap_local_header.DFUN},
                                                     ${bsap_local_header.SEQ},
                                                     ${bsap_local_header.SFUN},
                                                     ${bsap_local_header.NSB});
            }
            return true;
      %}
    ###############################################################################################
    ########################  Process data for bsap_global_header event  ##########################
    ###############################################################################################
    function proc_bsap_global_header(bsap_global_header: BSAP_Global_Header): bool
      %{

            if( ::bsap_global_header)
            {
                BifEvent::generate_bsap_global_header(connection()->bro_analyzer(),
                                                      connection()->bro_analyzer()->Conn(),
                                                      ${bsap_global_header.SER},
                                                      ${bsap_global_header.DADD},
                                                      ${bsap_global_header.SADD},
                                                      ${bsap_global_header.CTL},
                                                      ${bsap_global_header.DFUN},
                                                      ${bsap_global_header.SEQ},
                                                      ${bsap_global_header.SFUN},
                                                      ${bsap_global_header.NSB});
            }
            return true;
      %}

    ###############################################################################################
    #########################  Process data for bsap_rdb_request event  ###########################
    ###############################################################################################
    function proc_bsap_rdb_request(bsap_rdb_request: RDB_Request): bool
      %{
            setFunc(${bsap_rdb_request.func_code});

            if( ::bsap_rdb_request )
            {
                BifEvent::generate_bsap_rdb_request(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    ${bsap_rdb_request.func_code},
                                                    bytestring_to_val(${bsap_rdb_request.data}));
            }
            return true;
      %}

    ###############################################################################################
    ###########################  Process data for bsap_response event  ############################
    ###############################################################################################
    function proc_bsap_response(bsap_response: RDB_Response): bool
       %{
            uint32 response_status = 0;
            uint32 app_code = getResponseID();

            response_status = checkResponse(app_code);


            if( ::bsap_rdb_response )
            {
               BifEvent::generate_bsap_rdb_response(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    response_status,
                                                    bytestring_to_val(${bsap_response.data}));
            }
            return true;
       %}

    ###############################################################################################
    ########################  Process data for bsap_rdb_extention event  ##########################
    ###############################################################################################
    function proc_bsap_rdb_extension(bsap_rdb_extention: RDB_Extension): bool
        %{
            if( ::bsap_rdb_extension )
            {
               BifEvent::generate_bsap_rdb_extension(connection()->bro_analyzer(),
                                                     connection()->bro_analyzer()->Conn(),
                                                     ${bsap_rdb_extention.DFUN},
                                                     ${bsap_rdb_extention.SEQ},
                                                     ${bsap_rdb_extention.SFUN},
                                                     ${bsap_rdb_extention.NSB},
                                                     ${bsap_rdb_extention.XFUN},
                                                     bytestring_to_val(${bsap_rdb_extention.data}));
            }
            return true;
       %}



    ###############################################################################################
    ############################  Process data for proc_unknown event  ############################
    ###############################################################################################
    function proc_unknown(bsap_unknown: BSAP_Unknown): bool
        %{
            if( ::bsap_unknown )
            {
               BifEvent::generate_bsap_unknown(connection()->bro_analyzer(),
                                               connection()->bro_analyzer()->Conn(),
                                               bytestring_to_val(${bsap_unknown.data}));
            }
            return true;
        %}

};
