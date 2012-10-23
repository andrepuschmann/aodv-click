
/** CLICK script for use with real linux systems **/


//require(package "AODV");
require(library local.click);
require(library aodv_core.click);



elementclass ToNetwork{
	input[0]
		-> Queue(2000)
		-> ToDevice(tap0);
}

elementclass FromNetwork{
	$myaddr_ethernet |
	FromDevice(tap0)
		-> HostEtherFilter($myaddr_ethernet, DROP_OWN false, DROP_OTHER true)
		-> output;
}

tohost::ToHost(fake0);
fromhost::FromHost(fake0, fake, ETHER fake);



FromNetwork(fake) -> aodv_core::AODV_Core(fake) -> output::ToNetwork;

fromhost
	-> fromhost_cl :: Classifier(12/0806, 12/0800);
	fromhost_cl[0] 
		-> ARPResponder(0.0.0.0/0 1:1:1:1:1:1) 
		-> tohost;
	fromhost_cl[1]
		-> Strip(14)
		-> [1]aodv_core;
		
aodv_core[1] 
	-> EtherEncap(0x0800, 1:1:1:1:1:1, fake) // ensure ethernet for kernel
	-> tohost;

	
	
