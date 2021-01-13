// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_BSAP_SERIAL_BSAP_SERIAL_H
#define ANALYZER_PROTOCOL_BSAP_SERIAL_BSAP_SERIAL_H

#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "bsap_serial_pac.h"

namespace analyzer 
{ 
    namespace BSAP_SERIAL
    {
        class BSAP_SERIAL_Analyzer : public analyzer::Analyzer 
        {
            public:
                BSAP_SERIAL_Analyzer(Connection* conn);
                virtual ~BSAP_SERIAL_Analyzer();

                virtual void Done();

                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen);

                static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
                { 
                    return new BSAP_SERIAL_Analyzer(conn); 
                }

            protected:
                binpac::BSAP_SERIAL::BSAP_SERIAL_Conn* interp;
        };
    } 
} 

#endif