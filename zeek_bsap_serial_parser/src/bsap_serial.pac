## bsap_serial.pac
##
## Binpac BSAP_SERIAL Protocol Analyzer
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

analyzer BSAP_SERIAL withcontext {
    connection: BSAP_SERIAL_Conn;
    flow:       BSAP_SERIAL_Flow;
};

connection BSAP_SERIAL_Conn(bro_analyzer: BroAnalyzer) {
    upflow   = BSAP_SERIAL_Flow(true);
    downflow = BSAP_SERIAL_Flow(false);
};

%include bsap_serial-protocol.pac

flow BSAP_SERIAL_Flow(is_orig: bool) {
    datagram = BSAP_SERIAL_PDU(is_orig) withcontext(connection, this);
};

%include bsap_serial-analyzer.pac
