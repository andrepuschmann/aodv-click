#include <click/config.h>
#include "ext_aodv_problemdetector.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/args.hh>
#include <click/timestamp.hh>
#include <click/router.hh>
#include <click/args.hh>
#include <stdio.h>
#include <string.h>

#include <fstream>
#include "ext_aodv_cptracker.hh"

using namespace std;
CLICK_DECLS
ProblemDetector::ProblemDetector() :
		_counter(0), _prefix("pkt-")
{

}
ProblemDetector::~ProblemDetector()
{

}
int ProblemDetector::configure(Vector<String> &conf, ErrorHandler *errh)
{
	Args a(conf, this, errh);
	String t;
	if (a.read_p("PREFIX", t).execute() < 0)
	{
		errh->message("ProblemDetector: wrong parameter value");
		return -1;
	}
	if (t.length() > 0)
	{
		_prefix = t;
	}
	return 0;
}
int ProblemDetector::initialize(ErrorHandler *errh)
{
	Router *r = router();
	typedef Vector<Element*> Elements;
	Elements els = r->elements();

	_partners = NULL;
	_gpsr = NULL;

	for (Elements::iterator i = els.begin(); i != els.end(); ++i)
	{
		//click_chatter("Found %s\n", (*i)->class_name());
		if (!_partners)
		{
			_partners = dynamic_cast<CPTracker*>(*i);
		}
		if(!_gpsr)
		{
			_gpsr = dynamic_cast<GPSR*>(*i);
		}
	}
	if (!_partners)
	{
		errh->message("The ProblemDetector element needs, the elements CPTracker is initialized.");
		return -1;
	}

	if(!_gpsr)
	{
		errh->message("The ProblemDetector element needs, the elements GPSREelement is initialized.");
		return -1;
	}

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

						click_chatter("[%d] Problem detected %s <-> %s", Timestamp::now().timeval().tv_sec,
								src_ip.s().c_str()/*/iph->ip_src*/, dst_ip.s().c_str()/*/iph->ip_dst*/);
					}
				}

			}
		}
		output(0).push(p);
	}
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ProblemDetector)

