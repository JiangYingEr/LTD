from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, CPULimitedHost
from mininet.link import TCLink
 
class MyTopo(Topo):
    "Simple topology example."
 
    def __init__(self, switchCount = 48, linkCount=130, hostCount=48):
        Topo.__init__(self)
 
    # Set the host number based on switch count (for simplicity)
    	#hostCount = switchCount
 
    # Create a custom topology


 
    # Add switches
    	switches = []
    	for i in range(switchCount):
            switches.append(self.addSwitch('s{}'.format(i + 1)))
        
 
    # Add hosts
        hosts = []
    	for i in range(hostCount):
            hosts.append(self.addHost('h{}'.format(i + 1)))

        for i in range(hostCount):
            self.addLink(hosts[i], switches[i])
 
    # Add links
        real_link = 0
    	for i in range(switchCount):
            for j in range(i+1, switchCount):
                self.addLink(switches[i], switches[j])
                real_link += 1
                if real_link >= linkCount:
                   break
            if real_link >= linkCount:
                break
 
    # Return the custom topology
    	#return topology
 
topos = {'mytopo': (lambda: MyTopo())}
