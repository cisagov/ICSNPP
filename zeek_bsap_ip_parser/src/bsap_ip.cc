// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "bsap_ip.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::BSAP_IP;

BSAP_IP_Analyzer::BSAP_IP_Analyzer(Connection* c): analyzer::Analyzer("BSAP_IP", c)
{
    interp = new binpac::BSAP_IP::BSAP_IP_Conn(this);
}

BSAP_IP_Analyzer::~BSAP_IP_Analyzer()
{
    delete interp;
}

void BSAP_IP_Analyzer::Done()
{
    Analyzer::Done();
}

void BSAP_IP_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
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
