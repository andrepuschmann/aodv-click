// Copyright (c) 2004 by the University of Antwerp
// All rights reserved.
//

// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
#include <click/string.hh>
#include "click_aodv.hh"
#include "aodv_packetanalyzer.hh"

CLICK_DECLS

String AODVPacketAnalyzer::getTypeString(int message_type)
{
	switch (message_type)
	{
	case AODV_RREQ_MESSAGE:
		return AODV_RREQ_STRING;
	case AODV_RERR_MESSAGE:
		return AODV_RERR_STRING;
	case AODV_RREP_MESSAGE:
		return AODV_RREP_STRING;
	case AODV_RREP_ACK_MESSAGE:
		return AODV_RREP_ACK_STRING;
	default:
		assert(false);
	}
}

String AODVPacketAnalyzer::getMessageString(Packet *packet)
{
	// determine type using size
	const unsigned char *type = (packet->transport_header()+sizeof(struct click_udp));
	//RREP, HELLO
	if (*type == AODV_RREP_MESSAGE)
	{
		if (packet->ip_header()->ip_ttl == 1 && packet->ip_header()->ip_dst == INADDR_BROADCAST)
		{
			return AODV_HELLO_STRING;
		}
		else
		{
			return AODV_RREP_STRING;
		}
	}
	else if(*type == AODV_RERR_MESSAGE) // RERR
	{
		return AODV_RERR_STRING;
	}
	else if (*type == AODV_RREQ_MESSAGE)
	{ //RREQ
		return AODV_RREQ_STRING;
	}
	else if (*type == AODV_RREP_ACK_MESSAGE)
	{ //RREP-ACK
		return AODV_RREP_ACK_STRING;
	}
	else return AODV_DATA_STRING;
}

	int AODVPacketAnalyzer::getMessageType(Packet *packet)
	{
		return getMessageType(getMessageString(packet));
	}

	int AODVPacketAnalyzer::getMessageType(const String & type)
	{
		if (type == AODV_HELLO_STRING)
			return AODV_HELLO_MESSAGE;
		else if (type == AODV_RREP_STRING)
			return AODV_RREP_MESSAGE;
		else if (type == AODV_RREQ_STRING)
			return AODV_RREQ_MESSAGE;
		else if (type == AODV_RERR_STRING)
			return AODV_RERR_MESSAGE;
		else if (type == AODV_RREP_ACK_STRING)
			return AODV_RREP_ACK_MESSAGE;
		else if (type == AODV_DATA_STRING)
			return AODV_DATA_MESSAGE;
		else
			assert(false);
		// unknown type
	}

CLICK_ENDDECLS ELEMENT_PROVIDES(AODVPacketAnalyzer)
