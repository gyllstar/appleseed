"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import CPULimitedHost,RemoteController,OVSSwitch
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from argparse import ArgumentParser
from dpg_topos import PCountTopo
import os
from itertools import izip
import sys
import signal
import time
import subprocess
from subprocess import Popen
import csv



def write_pcount_expt_params(num_monitored_flows,num_hosts):
  w = csv.writer(open("~/appleseed/expt/pcount_parms.txt", "w"))
  w.writerow([num_monitored_flows,num_hosts])

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

	for switch in net.switches:
		for dst in net.hosts:
			switch.setARP(ip=dst.IP(), mac = dst.MAC())	



controller_pid=-1

def signal_handler(signal,frame):
	print "Ctrl+C pressed.  Killing controller process, then exiting."
	kill_cmd = "sudo kill -9 %s" %(controller_pid) 
	os.system(kill_cmd)
	sys.exit(0)	

signal.signal(signal.SIGINT, signal_handler)


topo_classes = ["PCountTopo"]

parser = ArgumentParser(description="starts a custom mininet topology and connects with a remote controller") 

parser.add_argument("--loss", dest="loss",type=float,help="link loss rate",default=5)
parser.add_argument("--ip", dest="ip",help="address of remote controller",default="192.168.1.3")
parser.add_argument("--topoclass", dest="topoclass",help="name of topology class to instantiate, options include = %s" %(topo_classes),default=topo_classes[0])
parser.add_argument("--num-unicast-flows", dest="num_unicast_flows",type=int,help="number of unicast flows to create for PCount simulation. ",default=10)
parser.add_argument("--num-monitor-flows", dest="num_monitor_flows",type=int,help="number of unicast flows to monitor create for PCount simulation. ",default=10)

args = parser.parse_args()

print "\n---------------------------------------------------- "
print "first a quick cleanup: running `mn -c' \n"
os.system("mn -c")
print "---------------------------------------------------- \n\n"

print "parsed command line arguments: %s" %(args)


topo=None
num_unicast_flows = args.num_unicast_flows
num_monitor_flows = args.num_monitor_flows
if args.topoclass == topo_classes[0]:
	topo = PCountTopo(loss=args.loss,num_flows=args.num_unicast_flows)  
else: 	
	print "\nError, found no matching class for name = %s. Valid inputs include: \n\t%s \n Exiting program" %(args.topoclass,topo_classes)
	os._exit(0)


# (1) write experiment parameters to file for appleseed controller to read
#write_pcount_expt_params(num_monitor_flows,num_unicast_flows)

# (2) start the appleseed controller
print "\n starting appleseed controller as Remote Controller"
sys.path.append('/home/mininet/appleseed')
#start_aseed_cmd = ['python', '/home/mininet/appleseed/pox.py', '--no-cli', 'appleseed', 'openflow.discovery', 'log.level --packet=INFO'] 
start_aseed_cmd = ['python', '/home/mininet/appleseed/pox.py', '--no-cli', 'appleseed', '--num_monitor_flows=%s' %(num_monitor_flows),'--num_unicast_flows=%s' %(num_unicast_flows),
                   '--true_loss_percentage=%s ' %(args.loss), 'openflow.discovery','log', '--file=ext/results/pcount.log,w'] 

os.chdir('/home/mininet/appleseed')
pid = Popen(start_aseed_cmd,shell=False).pid
controller_pid = pid + 1

# (3) connect to the appleseed controller
c_addr = "127.0.0.1"
c = RemoteController('c',ip=c_addr)

print "trying to connect to remote controller at %s ..."%(c_addr)
net = Mininet(topo=topo,link=TCLink,controller=lambda name: c,listenPort=6634)
print "connected to remote controller at %s"%(c_addr)



#net.build()
net.start()
#CLI( net )
#os._exit(0)



wait = 4
print "\n sleeping for %s seconds before sending any Mininet messages so as to allow all links to be discovered by the Appleseed controller. " %(wait)
time.sleep(wait)



print "\n\nrunning 1-hop pings to populate allow for edge switches to discover their adjacent hosts"
hosts = net.hosts

# (2) 1-hop pings: DONE

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

	
# (3) tell appleseed to install the m flow entries: TODO
staticArp(net)

# run a ping command from h1 to special address to trigger primary tree install
h1 = hosts[0]
special_ip = '10.99.99.99'
cmd_str = 'ping -c1 -W 1 %s' %(special_ip)
print "h1 %s" %(cmd_str)
h1.cmd(cmd_str)



#CLI(net)
#net.stop()
#os._exit(0)


#wait = 10
#print "\n sleeping for %s seconds to debug the controller" %(wait)
#time.sleep(wait)

# (4) start the 'm' flows: TODO
host_num = 1
rate = 60	# 60 msgs per second
for host_num in range(1,num_unicast_flows+1):
	host = hosts[host_num-1]
	dst_id = host_num + num_unicast_flows
	cmd = 'sudo python ~/cbr_flow.py %s %s %s > ~/cbr/h%s_cbr.out &' %(host_num,dst_id,rate,host_num)
	#cmd = 'sudo ping -c50 10.0.0.%s > ~/cbr/h%s_ping.out &' %(dst_id,host_num)
	print cmd
	host.cmd(cmd)

CLI(net)

#wait = 60
#print "\n sleeping for %s seconds to cbr flows to start " %(wait)
#time.sleep(wait)



net.stop()
