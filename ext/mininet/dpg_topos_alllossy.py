"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""



from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import CPULimitedHost,RemoteController
from mininet.net import Mininet
from mininet.log import setLogLevel
from argparse import ArgumentParser
from mininet.util import dumpNodeConnections

class H3S4( Topo ):
    "Simple topology example."

    def __init__( self, loss):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
	
	self.loss = loss

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        leftHost2 = self.addHost( 'h2' )
        rightHost = self.addHost( 'h3' )
        leftSwitch = self.addSwitch( 's4' )
        leftSwitch2 = self.addSwitch( 's5' )
        middleSwitch = self.addSwitch( 's6' )
        rightSwitch = self.addSwitch( 's7' )
	

        # Add links
        self.addLink( leftHost, leftSwitch , loss=self.loss ) #(h1,s4)
        self.addLink( leftHost2, leftSwitch2 , loss=self.loss ) #(h2,s5)
        self.addLink( leftSwitch, middleSwitch , loss=self.loss ) #(s4,s6)
        self.addLink( leftSwitch2, middleSwitch , loss=self.loss ) #(s5,s6)
        self.addLink( middleSwitch, rightSwitch , loss=self.loss ) #(s6,s7)
        self.addLink( rightSwitch, rightHost , loss=self.loss ) #(s7,h3)

	# preconfigure the ARP table
	arpNodes = [rightHost,rightSwitch]
	net = Mininet(self)
	
	print "\n dumping node connection info"	
	dumpNodeConnections(net.hosts)
	print "\n"

class H2S2( Topo ):
    "Simple topology example."

    def __init__( self,loss):
        "Create custom topo."
	self.loss = loss

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        leftSwitch = self.addSwitch( 's3' )
        rightSwitch = self.addSwitch( 's4' )

        # Add links
        self.addLink( leftHost, leftSwitch , loss=self.loss )
        self.addLink( leftSwitch, rightSwitch , loss=self.loss )
        self.addLink( rightSwitch, rightHost , loss=self.loss )


class H3S2( Topo ):
    "Simple topology example."

    def __init__(self,loss):
	super(H3S2,self).__init__()	
	self.loss = loss
        self.generate()

    def generate(self):
	"Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        s4 = self.addSwitch( 's4' )
        s5 = self.addSwitch( 's5' )

        # Add links
	#linkopts = dict(bw=10,delay='5ms',loss=10)
        #self.addLink( h1, s4 )
        self.addLink( h1, s4, loss=self.loss )
        self.addLink( h2, s4, loss=self.loss )
        #self.addLink( leftSwitch, rightSwitch,0,1,delay='5ms',loss=10)
        #self.addLink( leftSwitch, rightSwitch,loss=10)
        #self.addLink( leftSwitch, rightSwitch )
        self.addLink( s5, h3 , loss=self.loss )
        self.addLink( s4, s5 , loss=self.loss )
        #self.addLink( leftSwitch, rightSwitch, loss=self.loss)

	

class H3S3( Topo ):
    "Simple topology example."

    def __init__( self , loss):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
	self.loss = loss

        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        leftHost2 = self.addHost( 'h2' )
        rightHost = self.addHost( 'h3' )
        leftSwitch = self.addSwitch( 's4' )
        middleSwitch = self.addSwitch( 's5' )
        rightSwitch = self.addSwitch( 's6' )

        # Add links
        self.addLink( leftHost, leftSwitch , loss=self.loss )
        self.addLink( leftHost2, leftSwitch , loss=self.loss )
        self.addLink( leftSwitch, middleSwitch , loss=self.loss )
        self.addLink( middleSwitch, rightSwitch , loss=self.loss )
        self.addLink( rightSwitch, rightHost , loss=self.loss )


