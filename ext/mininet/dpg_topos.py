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


class H9S6( Topo ):
    "Simple topology example."

    def __init__(self,loss):
	super(H9S6,self).__init__()	
	self.loss = loss
        self.generate()

    def generate(self):
	"Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        h4 = self.addHost( 'h4' )
        h5 = self.addHost( 'h5' )
        h6 = self.addHost( 'h6' )
        h7 = self.addHost( 'h7' )
        h8 = self.addHost( 'h8' )
        h9 = self.addHost( 'h9' )
        s10 = self.addSwitch( 's10' )
        s11 = self.addSwitch( 's11' )
        s12 = self.addSwitch( 's12' )
        s13 = self.addSwitch( 's13' )
        s14 = self.addSwitch( 's14' )
        s15 = self.addSwitch( 's15' )

        # Add links

        self.addLink( h1, s12)
        self.addLink( h2, s13)
        self.addLink( h3, s10)
        self.addLink( h4, s10)
        self.addLink( h5, s14)
        self.addLink( h6, s14)
        self.addLink( h7, s15)
        self.addLink( h8, s15)
        self.addLink( h9, s15)
        self.addLink( s12, s11)
        self.addLink( s13, s11, loss=self.loss)
        self.addLink( s11, s10)
        self.addLink( s14, s10, loss=self.loss)
        self.addLink( s15, s10)


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
        self.addLink( leftHost, leftSwitch ) #(h1,s4)
        self.addLink( leftHost2, leftSwitch2 ) #(h2,s5)
        #self.addLink( leftSwitch, middleSwitch  ) #(s4,s6)
        self.addLink( leftSwitch, middleSwitch , loss=self.loss  ) #(s4,s6)
        self.addLink( leftSwitch2, middleSwitch ) #(s5,s6)
        self.addLink( middleSwitch, rightSwitch ) #(s6,s7)
        #self.addLink( middleSwitch, rightSwitch , loss=self.loss ) #(s6,s7)
        self.addLink( rightSwitch, rightHost  ) #(s7,h3)

	# preconfigure the ARP table
	#arpNodes = [rightHost,rightSwitch]
	#net = Mininet(self)
	
	#print "\n dumping node connection info"	
	#dumpNodeConnections(net.hosts)
	#print "\n"

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
        self.addLink( leftHost, leftSwitch )
        self.addLink( leftSwitch, rightSwitch , loss=self.loss )
        self.addLink( rightSwitch, rightHost )


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
        self.addLink( h1, s4)
        self.addLink( h2, s4)
        #self.addLink( leftSwitch, rightSwitch,0,1,delay='5ms',loss=10)
        #self.addLink( leftSwitch, rightSwitch,loss=10)
        #self.addLink( leftSwitch, rightSwitch )
        self.addLink( s5, h3 )
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
        self.addLink( leftHost, leftSwitch  )
        self.addLink( leftHost2, leftSwitch  )
        self.addLink( leftSwitch, middleSwitch, loss=self.loss )
        self.addLink( middleSwitch, rightSwitch )
        self.addLink( rightSwitch, rightHost )


