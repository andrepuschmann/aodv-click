#include <click/config.h>
#include "ext_aodv_problemdetector.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/args.hh>
#include <click/timestamp.hh>
#include <click/router.hh>
#include <click/args.hh>
#include <click/timer.hh>

#include <stdio.h>
#include <string.h>

#include <clicknet/ip.h>
#include <clicknet/udp.h>

#include <fstream>
#include "ext_aodv_cptracker.hh"

using namespace std;
CLICK_DECLS
ProblemDetector::ProblemDetector() :
		_counter(0), _timer(this), _srv_port(19000), _timeout(2)
{

}
ProblemDetector::~ProblemDetector()
{

}
int ProblemDetector::configure(Vector<String> &conf, ErrorHandler *errh)
{
	Args a(conf, this, errh);
	uint32_t timeout;
	if (a.read_mp("SERVERPORT",_srv_port).read_p("TIMEOUT", timeout).execute() < 0)
	{
		errh->message("EAODVProblemDetector: wrong parameter value. Expected SERVERPORT[, TIMEOUT in s]");
		return -1;
	}
	if (timeout>0)
	{
		_timeout = timeout;
	}
	click_chatter("Server port: %d\n", _srv_port);
	return 0;
}
int ProblemDetector::initialize(ErrorHandler *errh)
{
	Router *r = router();
	typedef Vector<Element*> Elements;
	Elements els = r->elements();

	_partners = NULL;

	for (Elements::iterator i = els.begin(); i != els.end(); ++i)
	{
		//click_chatter("Found %s\n", (*i)->class_name());
		if (!_partners)
		{
			_partners = dynamic_cast<CPTracker*>(*i);
		}

	}
	if (!_partners)
	{
		errh->message("The ProblemDetector element needs, the elements CPTracker is initialized.");
		return -1;
	}
	_timer.initialize(this);
	return 0;
}

void ProblemDetector::push(int, Packet *p)
{
	if (p)
	{
		struct click_ip* iph = (struct click_ip*) p->ip_header();
		if (iph->ip_v == 4)
		{
			IPAddress dst_ip = iph->ip_dst;
			IPAddress src_ip = iph->ip_src;
			if (!dst_ip.is_multicast())
			{
				CPTracker::CommPartner cp;
				if (_partners->getCommPartner(dst_ip, cp))
				{
					if (cp.status == CPTracker::ST_BIDIRECT)
					{
						_partners->updateStatus(dst_ip, CPTracker::ST_WAITING_FOR_RECOVERY);

						_timer.schedule_after_sec(_timeout);

						click_chatter("[%d] Problem detected %s <-> %s", Timestamp::now().timeval().tv_sec,
								src_ip.s().c_str()/*/iph->ip_src*/, dst_ip.s().c_str()/*/iph->ip_dst*/);
					}
				}

			}
		}
		output(0).push(p);
	}
}

void ProblemDetector::sendNotification()
{
	WritablePacket *pkt = Packet::make(sizeof(struct click_udp));
	struct click_udp *udphdr = (struct click_udp*)(pkt->data());
	udphdr->uh_dport = htons(_srv_port);
	udphdr->uh_sport = htons(_srv_port);
	udphdr->uh_ulen = htons(8);

	output(1).push(pkt);


}

void ProblemDetector::run_timer(Timer *t)
{
	if(cp.status == CPTracker::ST_WAITING_FOR_RECOVERY)
	{
		sendNotification();
	}

}

CLICK_ENDDECLS
EXPORT_ELEMENT(ProblemDetector)

