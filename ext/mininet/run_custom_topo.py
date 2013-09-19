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
from mininet.cli import CLI
from argparse import ArgumentParser
from dpg_topos import H2S2,H3S3,H3S2,H3S4,H9S6
import os


topo_classes = ["H3S2","H2S2","H3S3","H3S4","H9S6"]

parser = ArgumentParser(description="starts a custom mininet topology and connects with a remote controller") 

parser.add_argument("--loss", dest="loss",type=float,help="link loss rate",default=0)
parser.add_argument("--ip", dest="ip",help="address of remote controller",default="192.168.1.5")
parser.add_argument("--topoclass", dest="topoclass",help="name of topology class to instantiate, options include = %s" %(topo_classes),default=topo_classes[0])

args = parser.parse_args()

print "\n---------------------------------------------------- "
print "first a quick cleanup: running `mn -c' \n"
os.system("mn -c")
print "---------------------------------------------------- \n\n"

print "parsed command line arguments: %s" %(args)


#setLogLevel('debug')
topo=None
if args.topoclass == topo_classes[0]:
	topo = H3S2(loss=args.loss)	
elif args.topoclass == topo_classes[1]:
	topo = H2S2(loss=args.loss)	
elif args.topoclass == topo_classes[2]:
	topo = H3S3(loss=args.loss)	
elif args.topoclass == topo_classes[3]:
	topo = H3S4(loss=args.loss)	
elif args.topoclass == topo_classes[4]:
	topo = H9S6(loss=args.loss)	
else: 	
	print "\nError, found no matching class for name = %s. Valid inputs include: \n\t%s \n Exiting program" %(args.topoclass,topo_classes)
	os._exit(0)



c_addr = args.ip
c = RemoteController('c',ip=c_addr)

#net = Mininet(topo=topo,host=CPULimitedHost,link=TCLink)
#net = Mininet(topo=topo,link=TCLink,controller=c)
print "trying to connect to remote controller at %s ..."%(c_addr)
#net = Mininet(topo=topo,link=TCLink,controller=lambda name: c)
net = Mininet(topo=topo,link=TCLink,controller=lambda name: c,listenPort=6634)
print "connected to remote controller at %s"%(c_addr)

net.start()

print "\n\nhost list"
print net.hosts

print "\n\nswitch list:"
print net.switches


#h1,h2 = net.hosts[0], net.hosts[1]
#print h1.cmd('ping -c10 %s') %(h2.IP())
print "\n\nrunning a pingall command"
net.pingAll()

CLI(net)

net.stop()
