// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "ENIP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::enip;

ENIP_TCP_Analyzer::ENIP_TCP_Analyzer(Connection* c): tcp::TCP_ApplicationAnalyzer("ENIP_TCP", c) {
    interp = new binpac::ENIP::ENIP_Conn(this);
    had_gap = false;
    }

ENIP_TCP_Analyzer::~ENIP_TCP_Analyzer() {
    delete interp;
    }

void ENIP_TCP_Analyzer::Done() {
    tcp::TCP_ApplicationAnalyzer::Done();
    interp->FlowEOF(true);
    interp->FlowEOF(false);
    }

void ENIP_TCP_Analyzer::EndpointEOF(bool is_orig) {
    tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
    }

void ENIP_TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
    assert(TCP());
    if(had_gap)
        return;

    try {
        interp->NewData(orig, data, data + len);
        }
    catch(const binpac::Exception& e) {
        ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
        }
    }

void ENIP_TCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    had_gap = true;
    interp->NewGap(orig, len);
    }

ENIP_UDP_Analyzer::ENIP_UDP_Analyzer(Connection* c): analyzer::Analyzer("ENIP_UDP", c){
	interp = new binpac::ENIP::ENIP_Conn(this);
}

ENIP_UDP_Analyzer::~ENIP_UDP_Analyzer() {
    delete interp;
}

void ENIP_UDP_Analyzer::Done(){
	Analyzer::Done();
}

void ENIP_UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}