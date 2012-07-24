/*
 * AODVKnownClassifier.{cc,hh} -- classify incoming (RREQ) AODV packets
 * Bart Braem
 *
 */

// ALWAYS INCLUDE <click/config.h> FIRST
#include <click/config.h>
#include <click/error.hh>
#include <click/confparse.hh>
#include <clicknet/ip.h>

#include "click_aodv.hh"
#include "aodv_knownclassifier.hh"

CLICK_DECLS
AODVKnownClassifier::AODVKnownClassifier()
{
}

AODVKnownClassifier::~AODVKnownClassifier()
{
}

int AODVKnownClassifier::configure(Vector<String> &conf, ErrorHandler *errh)
{
	int res = cp_va_kparse(conf, this, errh, "NEIGHBOURS", cpkP + cpkM,
			cpElementCast, "AODVNeighbours", &neighbour_table, cpEnd);
	if (res < 0)
		return res;
	myIP = &neighbour_table->getMyIP();
	return res;
}

void AODVKnownClassifier::push(int port, Packet * p)
{
	assert(port == 0);
	assert(p);
	WritablePacket * packet = p->uniqueify();
	assert(packet);
	aodv_rreq_header * rreq = (aodv_rreq_header*) (packet->data()
			+ aodv_headeroffset);

	uint32_t rreqid = ntohl(rreq->rreqid);

	String key = String(long(rreqid));
	key += ' ';
	key += IPAddress(rreq->originator).s();

	// check RREQ buffer according to RFC 6.3	
	if (RREQBuffer.find_pair(key))
	{
		packet->kill();
		// click_chatter("discarded");
		return;
	}
	addKnownRREQ(key); // buffer for next time

	// increment hopcount according to RFC 6.5
	++rreq->hopcount;

	const click_ip * ipheader = packet->ip_header();

	/*click_chatter("in  RREQ %s -> %s; o: %s; d: %s HC=%d",
			IPAddress(ipheader->ip_src).s().c_str(),
			IPAddress(ipheader->ip_dst).s().c_str(),
			IPAddress(rreq->originator).s().c_str(),
			IPAddress(rreq->destination).s().c_str(), rreq->hopcount);*/

	uint32_t newlifetime = (2 * AODV_NET_TRAVERSAL_TIME)
			- (2 * rreq->hopcount * AODV_NODE_TRAVERSAL_TIME);

	neighbour_table->updateRoutetableEntry(rreq->originator,
			ntohl(rreq->originatorseqnr), rreq->hopcount, ipheader->ip_src,
			newlifetime);

	// RFC 6.5: "Whenever a RREQ message is received, ..." be certain, do update again
	neighbour_table->addLifeTime(rreq->originator, newlifetime);

	bool destinationOnly = rreq->jrgdureserved & (1 << 4);
	IPAddress* next = neighbour_table->nexthop(rreq->destination);
	bool invalidated = false;
	if(next)
	{
		if(*next==IPAddress(ipheader->ip_src))
		{
			neighbour_table->invalidateRoute(rreq->destination);
			invalidated = true;
		}
	}

	uint32_t * storedSeqNr = neighbour_table->getSequenceNumber(rreq->destination);

	if (rreq->destination == *myIP ||
			((!destinationOnly) && next && (!invalidated) &&
					(*storedSeqNr == ntohl(rreq->destinationseqnr)|| AODVNeighbours::largerSequenceNumber(*storedSeqNr, ntohl(rreq->destinationseqnr)))))
	{
		//click_chatter("destination found, replying");
		//if(next) neighbour_table->addPrecursor(*next,rreq->destination); // RFC 6.2
		if (next)
		{
			neighbour_table->addPrecursor(rreq->destination,IPAddress(ipheader->ip_src));
		}
		output(0).push(packet);
	}
	else
	{
		// RFC 6.5: "if a node does not generate a RREP...: update to maximum"
		if (storedSeqNr
				&& AODVNeighbours::largerSequenceNumber(*storedSeqNr,ntohl(rreq->destinationseqnr)))
		{
			rreq->destinationseqnr = htonl(*storedSeqNr);
		}
		click_ip * ipheader = packet->ip_header();
		if (ipheader->ip_ttl > 1)
		{
			--ipheader->ip_ttl;
			ipheader->ip_src = myIP->in_addr();
			output(1).push(packet);
		}
		else
		{
			// time's up, kill
			packet->kill();
		}
	}
	if(next)
	{
		delete next; // free memory
	}
	if(storedSeqNr)
	{
		delete storedSeqNr;
	}
}

void AODVKnownClassifier::cleanup(CleanupStage cleanupStage)
{
	for(PastRREQMap::iterator i=RREQBuffer.begin(); i!=RREQBuffer.end(); ++i)
	{
		//i.value()->unschedule();
		i.value()->clear();
		delete i.value();
	}
}

void AODVKnownClassifier::addKnownRREQ(const String & key)
{
	Timer * timer = new Timer(this);
	timer->initialize(this);
	timer->schedule_after_msec(AODV_PATH_DISCOVERY_TIME);

	RREQBuffer.insert(key, timer);
}

void AODVKnownClassifier::addKnownRREQ(uint32_t id, const IPAddress & ip)
{
	String key = String(long(id));
	key += ' ';
	key += ip.s();

	addKnownRREQ(key);
}

void AODVKnownClassifier::run_timer(Timer *t)
{
	for(PastRREQMap::iterator i = RREQBuffer.begin(); i!=RREQBuffer.end(); ++i)
	{
		if(i.value() == t)
		{
			RREQBuffer.remove(i.key());
			delete t;
			break;
		}
	}
}



// macro magic to use bighashmap
#include <click/bighashmap.cc>
#if EXPLICIT_TEMPLATE_INSTANCES
template class HashMap<String, Timer*>;
#endif

CLICK_ENDDECLS

EXPORT_ELEMENT(AODVKnownClassifier)

