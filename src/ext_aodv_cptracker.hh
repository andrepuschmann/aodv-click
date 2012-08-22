/*
 * =c
 * CPTracker()
 * =s tracking
 * tracks communication partners
 * =d
 * Tracks all the in- and outgoing packets for the host and stores the information
 * about established bidirectional communication into a table. The packets addressed to the
 * host are forwarded from INPUT1 to OUTPUT1, and the packets from the host are forwarded from INPUT2
 * to OUTPUT2
 *
 * =processing
 * two PUSH inputs, two PUSH outputs
 */

#ifndef EXT_AODV_CP_TRACKER_HH
#define EXT_AODV_CP_TRACKER_HH
#include <click/element.hh>
#include <click/timestamp.hh>
#include <click/hashtable.hh>
#include <click/ipaddress.hh>
#include <click/timer.hh>
CLICK_DECLS
class CPTracker : public Element
{
public:
	enum CP_STATUS
	{
		ST_FROM_HOST = 10,
		ST_TO_HOST = 20,
		ST_BIDIRECT = 30,
		ST_WAITING_FOR_RECOVERY = 40
	};
	typedef struct tagCommPartner
	{
		Timestamp ts;
		CP_STATUS status;
	}CommPartner;



private:
	typedef HashTable<IPAddress, CommPartner> CPTable;
	CPTable _data;
	Timer timer;

public:
        CPTracker();
        ~CPTracker();
    const char *class_name() const {return "EAODVCPTracker";}
    const char *port_count() const {return "2/2";}
    const char *processing() const {return PUSH;}
    int configure(Vector<String> &, ErrorHandler *);
    void push(int, Packet*);

    virtual void run_timer(Timer *t);
    virtual int initialize(ErrorHandler *errh);

    virtual void add_handlers();

    void cleanTable();

    bool getCommPartner(const IPAddress &addr, CommPartner &cp);
    void updateStatus(const IPAddress &addr, enum CP_STATUS);
    String readTable();
private:
    Packet* processFromHost(Packet *);
    Packet* processToHost(Packet *);
    static String readHandle(Element*, void*);

};
CLICK_ENDDECLS

#endif

