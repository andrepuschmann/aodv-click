#ifndef PROBLEM_DETECTOR_ELEM_HH
#define PROBLEM_DETECTOR_ELEM_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/timer.hh>
CLICK_DECLS
class CPTracker;

class ProblemDetector : public Element
{
public:
        ProblemDetector();
        ~ProblemDetector();
    const char *class_name() const {return "EAODVProblemDetector";}
    const char *port_count() const {return "1/2";}
    const char *processing() const {return PUSH;}
    int configure(Vector<String> &, ErrorHandler *);
    virtual int initialize(ErrorHandler *errh);
    void push(int, Packet*);
    void sendNotification();
    virtual void run_timer(Timer *t);
protected:
    int _counter;
    String _prefix;
    CPTracker *_partners;
    Timer _timer;
    uint16_t _srv_port;
    uint32_t _timeout;
};
CLICK_ENDDECLS

#endif

