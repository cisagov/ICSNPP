## bsap_ip.pac
##
## Binpac BSAP_IP Protocol Analyzer
##
## Author:  Devin Vollmer
## Contact: devin.vollmer@inl.gov
##
## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
%}

analyzer BSAP_IP withcontext {
    connection: BSAP_IP_Conn;
    flow:       BSAP_IP_Flow;
};

connection BSAP_IP_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = BSAP_IP_Flow(true);
    downflow = BSAP_IP_Flow(false);
};

%include bsap_ip-protocol.pac

flow BSAP_IP_Flow(is_orig: bool) {
    datagram = BSAP_IP_PDU(is_orig) withcontext(connection, this);
};

%include bsap_ip-analyzer.pac
