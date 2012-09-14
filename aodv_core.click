
/** AODV Core Module **/
require(package "AODV")

elementclass AODV_Core {
	$fake | 

	/**
	*	get IP data from system and forward to router and vice versa
	*/
	elementclass System{

		input[1]
			-> CheckIPHeader
			-> MarkIPHeader
			-> [0]output;
			
		input[0]
			-> CheckIPHeader()
			-> MarkIPHeader()
			-> [1]output;
	}

	/**
	* Classify ARP and others
	* input[0] from network
	* output[0] to network (ARP responses from me)
	* output[1] to IP data processor
	* output[2] to ARP querier (ARP responses from others)
	*/
	elementclass ClassifyARP{
		$myaddr, $myaddr_ethernet |
		
		// classifier output 0: ARP requests, output 1: ARP replies, output 2: rest
		input[0] 
			-> arpclass :: Classifier(12/0806 20/0001, 12/0806 20/0002, -);
		
		// reply requests and output to network
		arpclass[0] 
			-> ARPResponder($myaddr/*, $myaddr_ethernet*/)
			-> [0]output;
			
		arpclass[1] 
			-> [2]output
		
		arpclass[2] 
			-> CheckIPHeader(OFFSET 14)
			-> MarkIPHeader(14)
			-> [1]output;
	}

	/**
	*	classify AODV and not-AODV
	*	input[0] IP Packets
	*	output[0] AODV traffic
	*	output[1] not AODV traffic
	*/
	elementclass ClassifyIP {
		input[0]
			-> aodvpackets :: IPClassifier(dst udp port 654, -);
		
		aodvpackets[0]
			-> [0]output;
			
		aodvpackets[1]
			-> [1]output;
	}

	/**
	* classify the AODV packets
	* input[0] AODV packets
	* output[0] RREQ
	* output[1] RRER
	* output[2] HELLO
	* output[3] RREP
	* output[4] wrong type
	*
	*/
	elementclass ClassifyAODV{
		// distinguish AODV message type: 0: RREQ, 1: RERR, 2: HELLO (TTL = 1), 3: RREP, 4: wrong type
		input[0]
			-> aodvmessagetype :: Classifier(42/01, 42/03, 42/02 22/01, 42/02, - );
		
		aodvmessagetype[0]
			-> [0]output;
		aodvmessagetype[1]
			-> [1]output;
		aodvmessagetype[2]
			-> [2]output;
		aodvmessagetype[3]
			-> [3]output;
		aodvmessagetype[4]
			-> [4]output;
	}

	/**
	* handle route discovery
	* input[0] packets needing route discovery
	* input[1] RREP
	* output[0] packets with discovered routes (without ethernet header)
	* output[1] timed out packets, to ICMP error generation
	*/
	elementclass RouteDiscovery{
		$genrreq |
		input[0]
			-> [0]discovery :: AODVWaitingForDiscovery($genrreq,neighbours);
		input[1]
			-> [1]discovery;
		discovery[0]
			-> [0]output;
		discovery[1]
			-> [1]output;
			
			
		AODVLinkNeighboursDiscovery(neighbours,discovery);
	}


	neighbours :: AODVNeighbours(fake);

	rerr:: AODVGenerateRERR(neighbours)
		-> UDPIPEncap(fake, 654, 255.255.255.255, 654)
		-> EtherEncap(0x0800, fake, ff:ff:ff:ff:ff:ff)
		-> [0]output;

	hello::AODVHelloGenerator(neighbours)
		-> EtherEncap(0x0800, fake, ff:ff:ff:ff:ff:ff)
		-> [0]output;
	hello[1]
		-> [0]output;

	genrreq :: AODVGenerateRREQ(neighbours,knownclassifier)
		-> EtherEncap(0x0800, fake, ff:ff:ff:ff:ff:ff)
		-> hello;

	knownclassifier :: AODVKnownClassifier(neighbours);

	arpclass :: ClassifyARP(fake,fake);
	ipclass :: ClassifyIP;
	aodvclass :: ClassifyAODV;
	lookup :: AODVLookUpRoute(neighbours);
	arpquerier :: ARPQuerier(fake);
	routediscovery :: RouteDiscovery(genrreq);
	destinationclassifier :: AODVDestinationClassifier(neighbours);
	setrrepheaders::AODVSetRREPHeaders()
	routereply :: AODVGenerateRREP(neighbours,setrrepheaders);

	input[0] 
		-> arpclass;
	arpclass[0] 
		-> [0]output;
	arpclass[1]
		-> AODVTrackNeighbours(rerr, neighbours)
		-> ipclass;
	arpclass[2]
		-> [1]arpquerier;

	arpquerier
		-> [0]output;

	ipclass[0] 
		-> aodvclass;
	ipclass[1] 
		-> StripToNetworkHeader
		-> MarkIPHeader
		-> localhost::IPClassifier(dst host fake, - );
	localhost[0]
		-> system :: System;
	localhost[1]
		-> decttl :: DecIPTTL
		-> Paint(1) // mark packets to be forwarded
		-> lookup;
	decttl[1]
		-> ICMPError(fake, 11, 0)
		-> Paint(3)
		-> lookup;
	/*localhost[2]
		-> arpquerier;*/

	aodvclass[0]  // RREQ
		-> AODVUpdateNeighbours(neighbours)
		-> knownclassifier;
	aodvclass[1] //RERR
		-> [1]rerr;
	aodvclass[2] // HELLO
		-> AODVUpdateNeighbours(neighbours)
		-> Discard;
	aodvclass[3] // RREP
		-> AODVUpdateNeighbours(neighbours)
		-> destinationclassifier;
	aodvclass[4] // wrong type so unusable
		-> Discard; 

	knownclassifier[0]
		-> routereply;
	knownclassifier[1]
		-> StripToNetworkHeader
		-> SetIPChecksum
		-> EtherEncap(0x0800, fake, ff:ff:ff:ff:ff:ff)
		-> [0]output;

	routereply
		-> UDPIPEncap(fake, 654, 255.255.255.255, 654)
		-> setrrepheaders
		-> SetUDPChecksum
		-> SetIPChecksum
		-> [0]arpquerier;

	destinationclassifier[0]
		-> [1]routediscovery;
	destinationclassifier[1]
		-> StripToNetworkHeader
		-> MarkIPHeader
		-> DecIPTTL
		-> SetIPChecksum  // ip_src and ip_dst are changed
		-> Paint(2) // distinguish RREPs for precursors
		-> [0]arpquerier;
	destinationclassifier[2] // no nexthop -> discovery
		-> StripToNetworkHeader
		-> MarkIPHeader
		-> DecIPTTL
		-> Paint(2) // distinguish RREPs for precursors
		-> [0]routediscovery;
		
	system[1] -> [1]output;
	input[1] -> [1]system;
		
	system
		-> Paint(3)
		-> lookup;

	lookup[0] // known destination, dest IP annotation set
		-> StripToNetworkHeader
		->[0]arpquerier; 
	lookup[1] // unknown destination, routediscovery
		-> [0]routediscovery;
	lookup[2]
		-> rerr;
	routediscovery[0]
		-> SetIPChecksum
		-> StripToNetworkHeader
		-> [0]arpquerier;
	routediscovery[1]
		-> ICMPError(fake,3,1)
		-> system;
}

