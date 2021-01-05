%include binpac.pac
%include bro.pac

%extern{
    #include "events.bif.h"
%}

analyzer ENIP withcontext {
    connection: ENIP_Conn;
    flow:       ENIP_Flow;
};

connection ENIP_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = ENIP_Flow(true);
    downflow = ENIP_Flow(false);
};

%include enip-protocol.pac

flow ENIP_Flow(is_orig: bool) {
    datagram = ENIP_PDU(is_orig) withcontext(connection, this);
}

%include enip-analyzer.pac