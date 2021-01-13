// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "BSAP_SERIAL.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::BSAP_SERIAL;

BSAP_SERIAL_Analyzer::BSAP_SERIAL_Analyzer(Connection* c): analyzer::Analyzer("BSAP_SERIAL", c)
{
    interp = new binpac::BSAP_SERIAL::BSAP_SERIAL_Conn(this);
}

BSAP_SERIAL_Analyzer::~BSAP_SERIAL_Analyzer()
{
    delete interp;
}

void BSAP_SERIAL_Analyzer::Done()
{
    Analyzer::Done();
}

void BSAP_SERIAL_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
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
