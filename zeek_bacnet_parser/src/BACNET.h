// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_BACNET_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_BACNET_H

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"

#include "bacnet_pac.h"

namespace analyzer { 
	
	namespace BACNET 
	{

		class BACNET_Analyzer : public analyzer::Analyzer 
		{

			public:
				BACNET_Analyzer(Connection* conn);
				virtual ~BACNET_Analyzer();

				virtual void Done();
				
				virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);
				

				static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
					{ return new BACNET_Analyzer(conn); }

			protected:
				binpac::BACNET::BACNET_Conn* interp;
				
		};

	} 
} // namespace analyzer::* 

#endif