## enip-analyzer.pac
##
## Binpac Ethernet/IP (ENIP) Analyzer - Adds processing functions to ENIP_Flow to generate events.
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%header{

    typedef struct CIP_Request_Path {
        uint32 class_id, instance_id, attribute_id;
        string data_segment, other_path;

        CIP_Request_Path(){
            class_id = UINT32_MAX;
            instance_id = UINT32_MAX;
            attribute_id = UINT32_MAX;
            data_segment = "";
            other_path = "";
        }
        
    }CIP_Request_Path;

    uint32 get_number(uint8 size, uint8 x, const_bytestring data);
    CIP_Request_Path test_parse(const_bytestring data);

%}

%code{

    // Get uint32 number from data in request path
    uint32 get_number(uint8 size, uint8 x, const_bytestring data)
    {
        if(size == 0)
            return data[x];
        else if (size == 1)
            return (data[x] << 8) | data[x+1];
        else if (size == 2)
            return (data[x] << 24) | (data[x+1] << 13) | (data[x+2] << 8) | data[x+3];
        
        return UINT32_MAX;
    }

    // Parse request path and return CIP_Request_Path struct
    CIP_Request_Path test_parse(const_bytestring data)
    {
        CIP_Request_Path request_path;

        uint8 x = 0;
        uint8 data_length = data.length();

        while((x+1) < data_length){
            switch(data[x] >> 5){
                case 0: // Port Segment
                {
                    request_path.other_path += "Port Segment: ";
                    uint8 header = data[x];
                    if((header & 0xf) == 15){ // Check for Extended Port Identifier
                        request_path.other_path += fmt("Port Number = 0x%02x%02x ",data[x+2],data[x+1]);
                        x += 3;
                    }else{
                        request_path.other_path += fmt("Port Number = %d ",data[x] & 0xf);
                        x += 2;
                    }
                    if (((header >> 4) & 1) == 1){
                        request_path.other_path += "Link Address = ";
                        uint8 size = data[x];
                        x += 1;
                        for ( uint8 i = x; i < size+x; i++ )
                            request_path.other_path += data[i];
                        x += size + 1;
                    }else{
                        request_path.other_path += fmt("Link Address = %d",data[x]);
                        x += 1;
                    }
                    request_path.other_path += "; ";
                    break;
                }
                case 1: // Logical Segment
                {
                    uint8 choice = (data[x] & 0x1c) >> 2;
                    uint8 size = data[x] & 3;
                    x += 1;

                    if(choice == 0)
                        request_path.class_id = get_number(size, x, data);
                    else if(choice == 1)
                        request_path.instance_id = get_number(size, x, data);
                    else if(choice == 4)
                        request_path.attribute_id = get_number(size, x, data);
                    else
                        request_path.other_path += fmt("0x%x",get_number(size, x, data));
                    
                    if(size == 0)
                        x += 1;
                    else if(size ==1)
                        x += 2;
                    else
                        x += 4;
                    
                    
                    break;
                }
                case 2: // Network Segment
                {
                    request_path.other_path += "Network Segment: ";
                    uint8 header = data[x];
                    x += 1;
                    string network_choices[3] = {"Schedule","Fixed Tag","Production Inhibit Time"};
                    if(((header & 0x10) >> 4) == 0){
                        request_path.other_path += network_choices[(header & 0x7)] + "(";
                        request_path.other_path += fmt("0x%02x); ",data[x]);
                        x += 1;
                    }else{
                        uint8 size = data[x]*2;
                        x += 1;
                        for ( uint8 i = x; i < size+x; i++ )
                            request_path.other_path += data[i];
                        x += size;
                    }
                    return request_path;
                }
                case 3: // Symbolic Segment
                {
                    request_path.other_path += "Symbolic Segment: ";
                    x += 1;
                    uint8 size = data[x];
                    x += 1;
                    for ( uint8 i = x; i < size+x; i++ )
                        request_path.other_path += data[i];
                    x += size;
                    return request_path;
                }
                case 4: // Data Segment
                {
                    uint8 header = data[x];
                    x += 1;
                    if (header == 0x80){
                        uint8 size = data[x]*2;
                        for ( uint8 i = x; i < size+x; i++ )
                            request_path.data_segment += data[i];
                        x += size;
                    }else if(header == 0x91){
                        uint8 size = data[x];
                        x += 1;
                        for ( uint8 i = x; i < size+x; i++ )
                            request_path.data_segment += data[i];
                        x += size;
                        if ((size % 2) == 1)
                            x += 1;
                    }
                    return request_path;
                }
                default:
                {
                    request_path.other_path += "Unknown Segment: ";
                    for ( uint8 i = 0; i < data.length(); ++i )
                        request_path.other_path += fmt("%x",data[i]);
                    return request_path;
                }
            }

        }
        return request_path;
    }

%}

refine flow ENIP_Flow += {
    
    ###############################################################################################
    ############################  Process data for enip_header event  #############################
    ###############################################################################################
    function process_enip_header(enip_header: ENIP_Header): bool
        %{
            if ( ::enip_header )
            {
                BifEvent::generate_enip_header(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
                                              ${enip_header.command},
                                              ${enip_header.length},
                                              ${enip_header.session_handle},
                                              ${enip_header.status},
                                              bytestring_to_val(${enip_header.sender_context}),
                                              ${enip_header.options});
            }
            return true;
        %}

    ###############################################################################################
    #############################  Process data for cip_header event  #############################
    ###############################################################################################
    function process_cip_header(cip_header: CIP_Header): bool
        %{
            if ( ::cip_header )
            {
                CIP_Request_Path request_path;
                
                if(${cip_header.request_or_response} != 1)
                    request_path = test_parse(${cip_header.request_path.request_path});
                
                BifEvent::generate_cip_header(connection()->bro_analyzer(),
                                             connection()->bro_analyzer()->Conn(),
                                             ${cip_header.cip_sequence_count},
                                             ${cip_header.service_code},
                                             (${cip_header.request_or_response} == 1),
                                             ${cip_header.status},
                                             request_path.class_id,
                                             request_path.instance_id,
                                             request_path.attribute_id,
                                             new StringVal(request_path.data_segment),
                                             new StringVal(request_path.other_path));
            }
            return true;
        %}

    ###############################################################################################
    ###############################  Process data for cip_io event  ###############################
    ###############################################################################################
    function process_cip_io(cip_io_item: CIP_IO): bool
        %{
            if ( ::cip_io )
            {
                BifEvent::generate_cip_io(connection()->bro_analyzer(),
                                          connection()->bro_analyzer()->Conn(),
                                          ${cip_io_item.sequenced_address_item.connection_identifier},
                                          ${cip_io_item.sequenced_address_item.encap_sequence_number},
                                          ${cip_io_item.connected_data_length},
                                          bytestring_to_val(${cip_io_item.connected_data_item}));
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cip_identity event  ############################
    ###############################################################################################
    function process_cip_identity_item(identity_item: CIP_Identity_Item): bool
        %{
            if ( ::cip_identity )
            {
                BifEvent::generate_cip_identity(connection()->bro_analyzer(),
                                               connection()->bro_analyzer()->Conn(),
                                               ${identity_item.encapsulation_version},
                                               ${identity_item.socket_address.sin_addr},
                                               ${identity_item.socket_address.sin_port},
                                               ${identity_item.vendor_id},
                                               ${identity_item.device_type},
                                               ${identity_item.product_code},
                                               ${identity_item.revision_major},
                                               ${identity_item.revision_minor},
                                               ${identity_item.status},
                                               ${identity_item.serial_number},
                                               bytestring_to_val(${identity_item.product_name}),
                                               ${identity_item.state});
            }
            return true;
        %}

    ###############################################################################################
    ##########################  Process data for register_session event  ##########################
    ###############################################################################################
    function process_register_session(message: Register_Session): bool
        %{
            if ( ::register_session )
            {
                BifEvent::generate_register_session(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   ${message.protocol_version},
                                                   ${message.options_flags});
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for cip_security event  ############################
    ###############################################################################################
    function process_cip_security_item(security_item: CIP_Security_Item): bool
        %{
            if ( ::cip_security )
            {            
                BifEvent::generate_cip_security(connection()->bro_analyzer(),
                                               connection()->bro_analyzer()->Conn(),
                                               ${security_item.security_profile},
                                               ${security_item.cip_security_state},
                                               ${security_item.enip_security_state},
                                               ${security_item.iana_port_state});
            }
            return true;
        %}

    ###############################################################################################
    ##########################  Process data for enip_capability event  ###########################
    ###############################################################################################
    function process_enip_capability_item(enip_item: ENIP_Capability_Item): bool
        %{
            if ( ::enip_capability )
            {
                BifEvent::generate_enip_capability(connection()->bro_analyzer(),
                                                  connection()->bro_analyzer()->Conn(),
                                                  ${enip_item.enip_profile});
            }
            return true;
        %}

    ###############################################################################################
    ############################  Process data for enip_service event  ############################
    ###############################################################################################
    function process_service_item(service_item: Service_Item): bool
        %{
            if ( ::enip_service )
            {
                BifEvent::generate_enip_service(connection()->bro_analyzer(),
                                          connection()->bro_analyzer()->Conn(),
                                          ${service_item.protocol_version},
                                          ${service_item.capability_flags},
                                          bytestring_to_val(${service_item.service_name}));
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for connected_address event  ##########################
    ###############################################################################################
    function process_connected_address_item(address_item: Connected_Address_Item): bool
        %{
            if ( ::connected_address )
            {
                BifEvent::generate_connected_address(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    ${address_item.connection_identifier});
            }
            return true;
        %}

    ###############################################################################################
    #########################  Process data for sequenced_address event  ##########################
    ###############################################################################################
    function process_sequenced_address_item(address_item: Sequenced_Address_Item): bool
        %{
            if ( ::sequenced_address )
            {
                BifEvent::generate_sequenced_address(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    ${address_item.connection_identifier},
                                                    ${address_item.encap_sequence_number});
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for unconnected_message_dtls event  ######################
    ###############################################################################################
    function process_unconnected_message_dtls(message: Unconnected_Message_DTLS): bool
        %{
            if ( ::unconnected_message_dtls )
            {
                BifEvent::generate_unconnected_message_dtls(connection()->bro_analyzer(),
                                                           connection()->bro_analyzer()->Conn(),
                                                           ${message.unconn_message_type},
                                                           ${message.transaction_number},
                                                           ${message.status});
            }
            return true;
        %}

    ###############################################################################################
    ########################  Process data for socket_address_info event  #########################
    ###############################################################################################
    function process_socket_address_info(item: Socket_Address_Info_Item): bool
        %{
            if ( ::socket_address_info )
            {
                BifEvent::generate_socket_address_info(connection()->bro_analyzer(),
                                             connection()->bro_analyzer()->Conn(),
                                             ${item.sin_addr},
                                             ${item.sin_port});
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for get_attribute_all_response event  #####################
    ###############################################################################################
    function process_get_attribute_all_response(data: Get_Attributes_All_Response): bool
        %{
            if ( ::get_attribute_all_response )
            {
                BifEvent::generate_get_attribute_all_response(connection()->bro_analyzer(),
                                                             connection()->bro_analyzer()->Conn(),
                                                             bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for set_attribute_all_request event  ######################
    ###############################################################################################
    function process_set_attribute_all_request(data: Set_Attributes_All_Request): bool
        %{
            if ( ::set_attribute_all_request )
            {
                BifEvent::generate_set_attribute_all_request(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for get_attribute_list_request event  #####################
    ###############################################################################################
    function process_get_attribute_list_request(data: Get_Attribute_List_Request): bool
        %{
            if ( ::get_attribute_list_request )
            {
                string attribute_ids = fmt("%d",${data.attribute_list[0]});
                
                for(uint8 i=1; i<${data.attribute_count};i++)
                    attribute_ids += fmt(",%d",${data.attribute_list[i]});
                
                BifEvent::generate_get_attribute_list_request(connection()->bro_analyzer(),
                                                             connection()->bro_analyzer()->Conn(),
                                                             ${data.attribute_count},
                                                             new StringVal(attribute_ids));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for get_attribute_list_response event  #####################
    ###############################################################################################
    function process_get_attribute_list_response(data: Get_Attribute_List_Response): bool
        %{
            if ( ::get_attribute_list_response )
            {
                BifEvent::generate_get_attribute_list_response(connection()->bro_analyzer(),
                                                              connection()->bro_analyzer()->Conn(),
                                                              ${data.attribute_count},
                                                              bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for set_attribute_list_request event  #####################
    ###############################################################################################
    function process_set_attribute_list_request(data: Set_Attribute_List_Request): bool
        %{
            if ( ::set_attribute_list_request )
            {
                BifEvent::generate_set_attribute_list_request(connection()->bro_analyzer(),
                                                             connection()->bro_analyzer()->Conn(),
                                                             ${data.attribute_count},
                                                             bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for set_attribute_list_response event  #####################
    ###############################################################################################
    function process_set_attribute_list_response(data: Set_Attribute_List_Response): bool
        %{
            if ( ::set_attribute_list_response )
            {
                BifEvent::generate_set_attribute_list_response(connection()->bro_analyzer(),
                                                              connection()->bro_analyzer()->Conn(),
                                                              ${data.attribute_count},
                                                              bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ######################  Process data for multiple_service_request event  ######################
    ###############################################################################################
    function process_multiple_service_request(data: Multiple_Service_Packet_Request): bool
        %{
            if ( ::multiple_service_request )
            {
                uint8 c = 0; 
                uint8 service_count = ${data.service_count};
                string services = "";
                for(uint8 i=0; i < service_count;i++)
                {
                    c = ${data.service_offsets[i]};
                    services += fmt("0x%02x,",${data.services[c-(2*service_count)-2]});
                }
                
                BifEvent::generate_multiple_service_request(connection()->bro_analyzer(),
                                                           connection()->bro_analyzer()->Conn(),
                                                           service_count,
                                                           new StringVal(services));
            }
            return true;
        %}

    ###############################################################################################
    #####################  Process data for multiple_service_response event  ######################
    ###############################################################################################
    function process_multiple_service_response(data: Multiple_Service_Packet_Response): bool
        %{
            if ( ::multiple_service_response )
            {
                uint8 c = 0; 
                uint8 service_count = ${data.service_count};
                string services = "";
                for(uint8 i=0; i < service_count;i++)
                {
                    c = ${data.service_offsets[i]};
                    services += fmt("0x%02x,",${data.services[c-(2*service_count)-2]});
                }
                
                BifEvent::generate_multiple_service_response(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            service_count,
                                                            new StringVal(services));
            }
            return true;
        %}

    ###############################################################################################
    ###################  Process data for get_attribute_single_response event  ####################
    ###############################################################################################
    function process_get_attribute_single_response(data: Get_Attribute_Single_Response): bool
        %{
            if ( ::get_attribute_single_response )
            {
                BifEvent::generate_get_attribute_single_response(connection()->bro_analyzer(),
                                                                connection()->bro_analyzer()->Conn(),
                                                                bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}

    ###############################################################################################
    ####################  Process data for set_attribute_single_request event  ####################
    ###############################################################################################
    function process_set_attribute_single_request(data: Set_Attribute_Single_Request): bool
        %{
            if ( ::set_attribute_single_request )
            {
                BifEvent::generate_set_attribute_single_request(connection()->bro_analyzer(),
                                                               connection()->bro_analyzer()->Conn(),
                                                               ${data.attribute_id},
                                                               bytestring_to_val(${data.attribute_data}));
            }
            return true;
        %}
};
