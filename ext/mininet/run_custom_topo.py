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
from dpg_topos import H2S2,H3S3,H3S2,H3S4,H9S6,H4S8,H6S9,H6S10
import os
from itertools import izip

mcast_arp_map = {"10.10.10.10": "10:10:10:10:10:10", "10.11.11.11":"11:11:11:11:11:11"}

def pairwise(iterable):
	a = iter(iterable)
	return izip(a,a)

def staticArp( net ):
	""" Add all-pairs ARP enries + those for special multicast addresses.  This helps avoid the broadcast ARP requests. """
	for src in net.hosts:
		for dst in net.hosts:
			if src != dst:
#				print "%s adding (%s,%s)" %(src,dst.IP(),dst.MAC)
				src.setARP(ip=dst.IP(), mac = dst.MAC())	

	for ip in mcast_arp_map.keys():
		mac = mcast_arp_map[ip]
		for h in net.hosts:
#			print "%s adding (%s,%s)" %(h,ip,mac)
			h.setARP(ip=ip,mac=mac)
			
topo_classes = ["H3S2","H2S2","H3S3","H3S4","H9S6","H4S8","H6S9","H6S10"]

parser = ArgumentParser(description="starts a custom mininet topology and connects with a remote controller") 

parser.add_argument("--loss", dest="loss",type=float,help="link loss rate",default=0)
parser.add_argument("--ip", dest="ip",help="address of remote controller",default="192.168.1.3")
parser.add_argument("--topoclass", dest="topoclass",help="name of topology class to instantiate, options include = %s" %(topo_classes),default=topo_classes[0])

args = parser.parse_args()

print "\n---------------------------------------------------- "
print "first a quick cleanup: running `mn -c' \n"
os.system("mn -c")
print "---------------------------------------------------- \n\n"

print "parsed command line arguments: %s" %(args)


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
elif args.topoclass == topo_classes[5]:
  	topo = H4S8(loss=args.loss)  
elif args.topoclass == topo_classes[6]:
	topo = H6S9(loss=args.loss)  
elif args.topoclass == topo_classes[7]:
	topo = H6S10(loss=args.loss)  
else: 	
	print "\nError, found no matching class for name = %s. Valid inputs include: \n\t%s \n Exiting program" %(args.topoclass,topo_classes)
	os._exit(0)



c_addr = args.ip
c = RemoteController('c',ip=c_addr)

print "trying to connect to remote controller at %s ..."%(c_addr)
net = Mininet(topo=topo,link=TCLink,controller=lambda name: c,listenPort=6634)
print "connected to remote controller at %s"%(c_addr)

net.start()

print "\n\nhost list"
print net.hosts

print "\n\nswitch list:"
print net.switches


#print "\n\nrunning a pingall command"
#net.pingAll()

print "\n\nrunning 1-hop pings to populate allow for edge switches to discover their adjacent hosts"



hosts = net.hosts

# if we have an odd number of hosts add the first host to end of the list to
# ensure that a ping is run from each host
if len(hosts)%2==1:
	h1 = hosts[0]
	hosts.append(h1)

for h1,h2 in pairwise(hosts):
	cmd_str1 = 'ping -c1 -W 1 %s ' %(h2.IP())
	print "%s %s" %(h1,cmd_str1)
	h1.cmd(cmd_str1)
	cmd_str2 = 'ping -c1 -W 1 %s ' %(h1.IP())
	print "%s %s" %(h2,cmd_str2)
	h2.cmd(cmd_str2)

# wait to insert the ARP entries because we want the above pings to trigger an ARP message in at the controller so the switch to host mapping can be found
staticArp(net)
	
# run a ping command from h1 to special address to trigger primary tree install
h1 = hosts[0]
special_ip = '10.99.99.99'
cmd_str = 'ping -c1 -W 1 %s' %(special_ip)
print "h1 %s" %(cmd_str)
h1.cmd(cmd_str)


# The commented code block below is to run a ping btw all nodes.  
#
#for h1 in hosts:
#	for h2 in hosts:
#		if h1 != h2:
#			cmd_str = 'ping -c1 -W 1 %s ' %(h2.IP())
#			#cmd_str = 'ping -c1 -m 1 %s' %(h2.IP())
#			print "\t %s" %(cmd_str)
#			h1.cmd(cmd_str)
#			#h1.cmdPrint(cmd_str)


#print "running command `sudo python ~/sd.py' "
#h1.cmd("sudo python ~/sd.py")

CLI(net)



net.stop()
