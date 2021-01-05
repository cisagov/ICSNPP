// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_ENIP_H
#define ANALYZER_PROTOCOL_ENIP_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/udp/UDP.h"

#include "enip_pac.h"

namespace analyzer 
{ 
    namespace enip 
    {
        class ENIP_TCP_Analyzer : public tcp::TCP_ApplicationAnalyzer 
        {
            public:
                ENIP_TCP_Analyzer(Connection* conn);
                virtual ~ENIP_TCP_Analyzer();

                virtual void Done();
                virtual void DeliverStream(int len, const u_char* data, bool orig);
                virtual void Undelivered(uint64_t seq, int len, bool orig);

                virtual void EndpointEOF(bool is_orig);

                static analyzer::Analyzer* Instantiate(Connection* conn) 
                { 
                    return new ENIP_TCP_Analyzer(conn);
                }

            protected:
                binpac::ENIP::ENIP_Conn* interp;
                bool had_gap;
            };

        class ENIP_UDP_Analyzer : public analyzer::Analyzer 
		{

			public:
				ENIP_UDP_Analyzer(Connection* conn);
				virtual ~ENIP_UDP_Analyzer();
				virtual void Done();

				virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);
				
				static analyzer::Analyzer* Instantiate(Connection* conn)
					{ return new ENIP_UDP_Analyzer(conn); }

			protected:
				binpac::ENIP::ENIP_Conn* interp;
				
		};
        } 
    }

#endif