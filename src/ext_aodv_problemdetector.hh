#ifndef PROBLEM_DETECTOR_ELEM_HH
#define PROBLEM_DETECTOR_ELEM_HH
#include <click/element.hh>
#include <click/string.hh>
CLICK_DECLS
class CPTracker;
class GPSR;
class ProblemDetector : public Element
{
public:
        ProblemDetector();
        ~ProblemDetector();
    const char *class_name() const {return "EAODVProblemDetector";}
    const char *port_count() const {return "1/1";}
    const char *processing() const {return PUSH;}
    int configure(Vector<String> &, ErrorHandler *);
    virtual int initialize(ErrorHandler *errh);
    void push(int, Packet*);
protected:
    int _counter;
    String _prefix;
    CPTracker *_partners;
    GPSR *_gpsr;
};
CLICK_ENDDECLS

#endif

