// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_BSAP_IP_BSAP_IP_H
#define ANALYZER_PROTOCOL_BSAP_IP_BSAP_IP_H

#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "bsap_ip_pac.h"

namespace analyzer 
{ 
    namespace BSAP_IP 
    {
        class BSAP_IP_Analyzer : public analyzer::Analyzer 
        {
            public:
                BSAP_IP_Analyzer(Connection* conn);
                virtual ~BSAP_IP_Analyzer();

                virtual void Done();

                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen);

                static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
                { 
                    return new BSAP_IP_Analyzer(conn); 
                }

            protected:
                binpac::BSAP_IP::BSAP_IP_Conn* interp;
        };
    } 
} 

#endif