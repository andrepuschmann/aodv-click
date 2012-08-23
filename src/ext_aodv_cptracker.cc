#include <click/config.h>
#include "ext_aodv_cptracker.hh"
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/args.hh>
#include <click/timestamp.hh>
#include <click/straccum.hh>
#include <stdio.h>
#include <string.h>

CLICK_DECLS
EAODVCPTracker::EAODVCPTracker() :
		timer(this)
{

}
EAODVCPTracker::~EAODVCPTracker()
{

}
int EAODVCPTracker::configure(Vector<String> &/*conf*/, ErrorHandler */*errh*/)
{

	return 0;
}
void EAODVCPTracker::push(int gate, Packet *p)
{
	if (p)
	{
		Packet *p_out = NULL;
		switch (gate)
		{
		case 0:
			p_out = processToHost(p);
			break;
		case 1:
			p_out = processFromHost(p);
			break;
		}
		if (p_out)
		{
			output(gate).push(p);
		}
	}
}

Packet* EAODVCPTracker::processFromHost(Packet *p)
{
	struct click_ip const *iph =
			reinterpret_cast<const struct click_ip *>(p->data());IPAddress dst_ip(iph->ip_dst);

			if(!dst_ip.is_multicast())
			{
				if(_data.find(dst_ip)!=_data.end())
				{
					if(_data[dst_ip].status == ST_TO_HOST)
					{
						_data[dst_ip].status = ST_BIDIRECT;
					}
					else if(_data[dst_ip].status == ST_FROM_HOST)
					{
						_data[dst_ip].ts = Timestamp::now();
					}
				}
				else
				{
					CommPartner cp;
					cp.status = ST_FROM_HOST;
					cp.ts = Timestamp::now();
					_data[dst_ip]=cp;
				}

				//click_chatter("[%d] (status %d)to %s\n", _data[dst_ip].ts.timeval().tv_sec,_data[dst_ip].status, dst_ip.s().c_str());
			}
			return p;
		}
Packet* EAODVCPTracker::processToHost(Packet *p)
{
	struct click_ip const *iph =
			reinterpret_cast<const struct click_ip *>(p->data());

IPAddress			src_ip(iph->ip_src);

			if((iph->ip_hl > 5) && (!src_ip.is_multicast()))
			{
				int offset = 20;
				bool found = false;
				while(offset < iph->ip_hl * 4)
				{
					if(*(p->data() + offset) == 0xDD)
					{
						found = true;
						break;
					}
					else
					{
						offset += *(p->data() + offset + 1);
					}

				}
				if(found)
				{
					CommPartner cp;

					cp.ts = Timestamp::now();

					if(_data.find(src_ip)!=_data.end())
					{
						cp.status = _data[src_ip].status;
						if(cp.status == ST_FROM_HOST || cp.status == ST_WAITING_FOR_RECOVERY)
						{
							cp.status = ST_BIDIRECT;
						}
					}
					else
					{
						cp.status = ST_TO_HOST;
					}
					_data[src_ip]=cp;
					//click_chatter("[%d] (state %d) from %s\n", cp.ts.timeval().tv_sec,cp.status ,src_ip.s().c_str());
				}
			}
			return p;
		}

int EAODVCPTracker::initialize(ErrorHandler*)
{
	timer.initialize(this);
	timer.schedule_after_sec(2 * 60);
	return 0;
}
void EAODVCPTracker::run_timer(Timer* t)
{
	if (t == &timer)
	{

		cleanTable();
		timer.reschedule_after_sec(2 * 60);
	}
}

bool EAODVCPTracker::getCommPartner(const IPAddress &addr, CommPartner & cp)
{
	if (_data.find(addr) != _data.end())
	{
		cp = _data[addr];
		return true;
	}
	else
	{
		return false;
	}
}

void EAODVCPTracker::cleanTable()
{
	CPTable::iterator i = _data.begin();
	Timestamp ts(Timestamp::now().timeval().tv_sec - 2 * 60);
	while (i != _data.end())
	{
		if (i->second.ts < ts && i->second.status!=ST_WAITING_FOR_RECOVERY)
		{
			_data.erase(i->first);
			i = _data.begin();
		}
		else
		{
			++i;
		}
	}
	click_chatter("CPTracer: table was cleaned\n");
}
void EAODVCPTracker::add_handlers()
{
	add_read_handler("table", &readHandle, (const void*) NULL);
}
String EAODVCPTracker::readTable()
{
	StringAccum acc;
	if (_data.empty())
	{
		acc << "The Communication Partner Tracking table is empty\n";
	}
	else
	{
		for (CPTable::iterator i = _data.begin(); i != _data.end(); ++i)
		{

			switch (i->second.status)
			{
			case ST_FROM_HOST:
				acc << "[ TO  ] ";
				break;
			case ST_TO_HOST:
				acc << "[FROM ] ";
				break;
			case ST_BIDIRECT:
				acc << "[BIDIR] ";
				break;
			case ST_WAITING_FOR_RECOVERY:
				acc << "[RECOV] ";
				break;
			default:
				acc << "[ ??? ] ";
				break;
			}
			acc << i->first.s();
			acc << " @ " << i->second.ts<<"\n";
		}
	}
	return acc.take_string();
}

void EAODVCPTracker::updateStatus(const IPAddress & addr,
		enum EAODVCPTracker::CP_STATUS stat)
{
	if (_data.find(addr) != _data.end())
	{
		_data[addr].status = stat;
	}

}

String EAODVCPTracker::readHandle(Element* e, void *)
{
	EAODVCPTracker *me = dynamic_cast<EAODVCPTracker*>(e);
	return me->readTable();
}
CLICK_ENDDECLS
EXPORT_ELEMENT(CPTracker)

